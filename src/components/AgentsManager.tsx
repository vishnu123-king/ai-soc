import React, { useState } from 'react';
import {
  Server,
  Activity,
  CheckCircle,
  AlertCircle,
  RefreshCw,
  Copy,
  Check,
  Terminal,
  Shield,
  Radio,
  Cpu,
  Globe,
  Clock,
  Play,
  Zap,
} from 'lucide-react';
import { Agent } from '../types';
import { sendAgentHeartbeat, runSimulation } from '../services/api';

interface AgentsManagerProps {
  agents: Agent[];
  onRefresh: () => void;
  loading: boolean;
  onFilterAgentLogs: (hostname: string) => void;
}

export const AgentsManager: React.FC<AgentsManagerProps> = ({
  agents,
  onRefresh,
  loading,
  onFilterAgentLogs,
}) => {
  const [copiedText, setCopiedText] = useState<string | null>(null);
  const [pingingAgent, setPingingAgent] = useState<string | null>(null);
  const [pingStatus, setPingStatus] = useState<Record<string, string>>({});
  const [isSimulatingAgent, setIsSimulatingAgent] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedText(id);
    setTimeout(() => setCopiedText(null), 2500);
  };

  const handlePing = async (agentId: string) => {
    try {
      setPingingAgent(agentId);
      await sendAgentHeartbeat(agentId);
      setPingStatus((prev) => ({ ...prev, [agentId]: 'Heartbeat acknowledged (ONLINE)' }));
      onRefresh();
    } catch (err: any) {
      setPingStatus((prev) => ({ ...prev, [agentId]: `Ping failed: ${err.message}` }));
    } finally {
      setPingingAgent(null);
    }
  };

  const handleSimulateAttackOnAgent = async (agent: Agent) => {
    try {
      setIsSimulatingAgent(agent.agent_id);
      await runSimulation('full_kill_chain', agent.hostname, agent.agent_id);
      setPingStatus((prev) => ({ ...prev, [agent.agent_id]: 'Simulation attack sequence dispatched!' }));
      onRefresh();
    } catch (err: any) {
      setPingStatus((prev) => ({ ...prev, [agent.agent_id]: `Simulation error: ${err.message}` }));
    } finally {
      setIsSimulatingAgent(null);
    }
  };

  const totalAgents = agents.length;
  const onlineAgents = agents.filter((a) => a.status === 'ONLINE').length;
  const totalEventsFromAgents = agents.reduce((acc, a) => acc + (a.event_count || 0), 0);

  const centralSocUrl = typeof window !== 'undefined' ? window.location.origin : 'http://localhost:3000';

  const registerCommand = `cd aisoc-agent
python3 -m aisoc_agent.main register -c config/agent.conf`;

  const startDaemonCommand = `cd aisoc-agent
python3 -m aisoc_agent.main start -c config/agent.conf`;

  const diagnosticCommand = `cd aisoc-agent
python3 -m aisoc_agent.main test -c config/agent.conf`;

  return (
    <div className="space-y-6">
      {/* KPI Header Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-slate-400">Enrolled Linux Agents</span>
            <div className="text-2xl font-bold text-white tracking-tight mt-1">{totalAgents}</div>
            <span className="text-[11px] text-slate-500">Fleet endpoints registered</span>
          </div>
          <div className="p-3 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Server className="w-6 h-6" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-slate-400">Live Online Endpoints</span>
            <div className="text-2xl font-bold text-emerald-400 tracking-tight mt-1">
              {onlineAgents} <span className="text-xs text-slate-400 font-normal">/ {totalAgents}</span>
            </div>
            <span className="text-[11px] text-emerald-500/80 flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Active Heartbeat Bus
            </span>
          </div>
          <div className="p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/30 text-emerald-400">
            <Radio className="w-6 h-6" />
          </div>
        </div>

        <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-sm flex items-center justify-between">
          <div>
            <span className="text-xs font-medium text-slate-400">Agent Ingested Events</span>
            <div className="text-2xl font-bold text-cyan-400 tracking-tight mt-1">{totalEventsFromAgents}</div>
            <span className="text-[11px] text-slate-500">Continuous telemetry normalized</span>
          </div>
          <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30 text-purple-400">
            <Activity className="w-6 h-6" />
          </div>
        </div>
      </div>

      {/* Agents Table Section */}
      <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
        <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/70">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Server className="w-4 h-4 text-cyan-400" />
              Connected Linux Agent Fleet
            </h3>
            <p className="text-xs text-slate-400">
              Live endpoints reporting auth, process, privilege, and socket telemetry into the Central SOC
            </p>
          </div>

          <button
            onClick={onRefresh}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Refresh Agents</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-slate-950/50 text-slate-400 font-medium">
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Agent ID & Hostname</th>
                <th className="py-3 px-4">Operating System</th>
                <th className="py-3 px-4">IP Address</th>
                <th className="py-3 px-4">Version</th>
                <th className="py-3 px-4">Last Heartbeat</th>
                <th className="py-3 px-4">Events</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {agents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-8 text-center text-slate-500 font-sans">
                    No endpoint agents enrolled yet. Follow enrollment instructions below to connect your first agent.
                  </td>
                </tr>
              ) : (
                agents.map((agent) => {
                  const isOnline = agent.status === 'ONLINE';
                  const lastSeenDate = new Date(agent.last_seen);
                  const secondsAgo = Math.round((Date.now() - lastSeenDate.getTime()) / 1000);
                  const formattedTime =
                    secondsAgo < 60
                      ? `${secondsAgo}s ago`
                      : secondsAgo < 3600
                      ? `${Math.round(secondsAgo / 60)}m ago`
                      : lastSeenDate.toLocaleTimeString();

                  return (
                    <tr key={agent.agent_id} className="hover:bg-slate-800/40 transition">
                      {/* Status */}
                      <td className="py-3 px-4 font-sans">
                        <span
                          className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-semibold ${
                            isOnline
                              ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800/60'
                              : 'bg-amber-950/80 text-amber-400 border border-amber-800/60'
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              isOnline ? 'bg-emerald-400 animate-pulse' : 'bg-amber-400'
                            }`}
                          />
                          {agent.status}
                        </span>
                      </td>

                      {/* Agent ID & Hostname */}
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white text-xs">{agent.hostname}</div>
                        <div className="text-[11px] text-slate-500">{agent.agent_id}</div>
                      </td>

                      {/* Operating System */}
                      <td className="py-3 px-4 font-sans text-slate-300 text-xs">
                        <div className="flex items-center gap-1.5">
                          <Cpu className="w-3.5 h-3.5 text-slate-500" />
                          <span>{agent.operating_system}</span>
                        </div>
                      </td>

                      {/* IP Address */}
                      <td className="py-3 px-4 text-cyan-400">{agent.ip_address}</td>

                      {/* Version */}
                      <td className="py-3 px-4 text-slate-400">v{agent.agent_version}</td>

                      {/* Last Heartbeat */}
                      <td className="py-3 px-4 text-slate-300">
                        <div className="flex items-center gap-1">
                          <Clock className="w-3 h-3 text-slate-500" />
                          <span>{formattedTime}</span>
                        </div>
                      </td>

                      {/* Events Count */}
                      <td className="py-3 px-4 text-white font-bold">{agent.event_count || 0}</td>

                      {/* Actions */}
                      <td className="py-3 px-4 text-right font-sans space-x-1.5 whitespace-nowrap">
                        <button
                          onClick={() => handlePing(agent.agent_id)}
                          disabled={pingingAgent === agent.agent_id}
                          className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-[11px] font-semibold transition"
                          title="Send instant keep-alive ping heartbeat"
                        >
                          {pingingAgent === agent.agent_id ? 'Pinging...' : 'Ping'}
                        </button>

                        <button
                          onClick={() => handleSimulateAttackOnAgent(agent)}
                          disabled={isSimulatingAgent === agent.agent_id}
                          className="px-2 py-1 rounded bg-rose-500/15 hover:bg-rose-500/25 text-rose-400 border border-rose-500/30 text-[11px] font-semibold transition"
                          title="Simulate intrusion sequence targeting this host"
                        >
                          {isSimulatingAgent === agent.agent_id ? 'Simulating...' : 'Attack Test'}
                        </button>

                        <button
                          onClick={() => onFilterAgentLogs(agent.hostname)}
                          className="px-2 py-1 rounded bg-cyan-500/15 hover:bg-cyan-500/25 text-cyan-400 border border-cyan-500/30 text-[11px] font-semibold transition"
                          title="View telemetry logs for this agent"
                        >
                          View Logs
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Feedback message banner */}
        {Object.keys(pingStatus).length > 0 && (
          <div className="p-3 bg-slate-950 border-t border-slate-800 text-xs text-slate-300 space-y-1 font-mono">
            {Object.entries(pingStatus).map(([id, msg]) => (
              <div key={id} className="flex items-center gap-2">
                <CheckCircle className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                <span>
                  [{id}]: {msg}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Agent Enrollment Guide & CLI Diagnostics */}
      <div className="p-6 rounded-2xl bg-gradient-to-br from-slate-900 via-slate-900 to-slate-950 border border-slate-800 shadow-md">
        <div className="flex items-center gap-2 mb-2">
          <span className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Terminal className="w-5 h-5" />
          </span>
          <h3 className="text-base font-bold text-white">Endpoint Agent Enrollment & Setup Guide</h3>
        </div>
        <p className="text-xs text-slate-400 mb-6">
          Deploy the lightweight <code className="text-cyan-300 font-mono">aisoc-agent</code> daemon on any Linux endpoint
          to continuously stream syslog, auditd, process executions, and network sockets directly to this dashboard.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Step 1 */}
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="text-cyan-400 font-mono text-xs font-bold mb-1">STEP 1 &bull; ENROLL AGENT</div>
              <p className="text-slate-400 text-xs mb-3">
                Register the host identity and acquire a cryptographically secured bearer token.
              </p>
              <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                {registerCommand}
              </pre>
            </div>
            <button
              onClick={() => copyToClipboard(registerCommand, 'cmd1')}
              className="mt-3 flex items-center justify-center gap-1.5 w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
            >
              {copiedText === 'cmd1' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" /> Copy Command
                </>
              )}
            </button>
          </div>

          {/* Step 2 */}
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="text-cyan-400 font-mono text-xs font-bold mb-1">STEP 2 &bull; START TELEMETRY DAEMON</div>
              <p className="text-slate-400 text-xs mb-3">
                Starts continuous collectors for auth.log, auditd, process spawns, and background batch shipper.
              </p>
              <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                {startDaemonCommand}
              </pre>
            </div>
            <button
              onClick={() => copyToClipboard(startDaemonCommand, 'cmd2')}
              className="mt-3 flex items-center justify-center gap-1.5 w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
            >
              {copiedText === 'cmd2' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" /> Copy Command
                </>
              )}
            </button>
          </div>

          {/* Step 3 */}
          <div className="p-4 rounded-xl bg-slate-950/70 border border-slate-800 flex flex-col justify-between">
            <div>
              <div className="text-cyan-400 font-mono text-xs font-bold mb-1">STEP 3 &bull; RUN DIAGNOSTICS</div>
              <p className="text-slate-400 text-xs mb-3">
                Executes 4-step pipeline test: token check, ping, heartbeat acknowledgment, and sample ingestion.
              </p>
              <pre className="p-2.5 rounded bg-slate-900 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                {diagnosticCommand}
              </pre>
            </div>
            <button
              onClick={() => copyToClipboard(diagnosticCommand, 'cmd3')}
              className="mt-3 flex items-center justify-center gap-1.5 w-full py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition"
            >
              {copiedText === 'cmd3' ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" /> Copy Command
                </>
              )}
            </button>
          </div>
        </div>

        {/* Central SOC Target Config Snippet */}
        <div className="mt-4 p-3 rounded-lg bg-slate-950/90 border border-slate-800 text-xs text-slate-400 flex flex-col sm:flex-row items-center justify-between gap-2 font-mono">
          <div>
            <span className="text-slate-500">Config Target: </span>
            <span className="text-cyan-300">CENTRAL_SOC_URL = {centralSocUrl}</span>
          </div>
          <button
            onClick={() => copyToClipboard(`CENTRAL_SOC_URL=${centralSocUrl}`, 'env')}
            className="text-xs text-cyan-400 hover:text-cyan-300 underline font-sans"
          >
            {copiedText === 'env' ? 'Copied URL!' : 'Copy Target Env'}
          </button>
        </div>
      </div>
    </div>
  );
};
