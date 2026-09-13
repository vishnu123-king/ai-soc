import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { StatCards } from './components/StatCards';
import { ChartsView } from './components/ChartsView';
import { IncidentsTable } from './components/IncidentsTable';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import { LiveLogStream } from './components/LiveLogStream';
import { AttackSimulator } from './components/AttackSimulator';
import { RulesAndMitreView } from './components/RulesAndMitreView';
import { AgentsManager } from './components/AgentsManager';
import { fetchStats, fetchIncidents, fetchLogs, fetchIncidentDetail, seedSampleAttack, fetchAgents } from './services/api';
import { DashboardStats, Incident, SecurityLog, Alert, Agent } from './types';
import { AlertOctagon, BellRing, CheckCircle, ExternalLink, Shield } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const selectedIncidentRef = useRef<Incident | null>(null);
  selectedIncidentRef.current = selectedIncident;
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<{ title: string; desc: string; type: 'alert' | 'success' } | null>(
    null
  );
  const [logHostFilter, setLogHostFilter] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);

  // Load initial application state
  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [st, inc, lg, ag] = await Promise.all([
        fetchStats(),
        fetchIncidents(),
        fetchLogs(100),
        fetchAgents().catch(() => []),
      ]);
      setStats(st);
      setIncidents(inc);
      setLogs(lg);
      setAgents(ag);
    } catch (err) {
      console.error('Failed to load SOC dashboard telemetry:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      fetchStats().then(setStats).catch(() => {});
      fetchIncidents().then(setIncidents).catch(() => {});
      fetchLogs(100).then(setLogs).catch(() => {});
      fetchAgents().then(setAgents).catch(() => {});
    }, 4000);
    return () => clearInterval(interval);
  }, [loadData]);

  // WebSocket Live Security Telemetry Connection
  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimeout: any = null;
    let pingInterval: any = null;
    let isUnmounted = false;

    const connectWs = () => {
      if (isUnmounted) return;
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        return;
      }

      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      try {
        socket = new WebSocket(wsUrl);
        wsRef.current = socket;

        socket.onopen = () => {
          if (isUnmounted) {
            socket?.close();
            return;
          }
          setWsConnected(true);

          // Start 15s keep-alive heartbeat to prevent proxy timeout
          if (pingInterval) clearInterval(pingInterval);
          pingInterval = setInterval(() => {
            if (socket && socket.readyState === WebSocket.OPEN) {
              socket.send('ping');
            }
          }, 15000);
        };

        socket.onmessage = (event) => {
          try {
            if (event.data === 'pong') return;
            const payload = JSON.parse(event.data);
            const msgType = payload.type;
            const data = payload.data;

            if (msgType === 'NEW_LOG' || msgType === 'EVENT_INGESTED') {
              setLogs((prev) => [
                {
                  id: data.id,
                  timestamp: data.timestamp,
                  hostname: data.hostname,
                  event_type: data.event_type,
                  action: data.action,
                  process: data.process,
                  command: data.command,
                  status: data.status,
                  source_ip: data.source_ip,
                  username: data.username,
                  raw_message: data.raw_message || `${data.event_type} on ${data.hostname} (${data.status})`,
                },
                ...prev.filter((l) => l.id !== data.id).slice(0, 150),
              ]);
              fetchStats().then(setStats).catch(() => {});
              fetchAgents().then(setAgents).catch(() => {});
            } else if (msgType === 'NEW_ALERT' || msgType === 'DETECTION_TRIGGERED') {
              setToastMessage({
                title: `Security Alert: ${data.rule_name || data.title}`,
                desc: `${data.description || data.title} on ${data.hostname}`,
                type: 'alert',
              });
              fetchStats().then(setStats).catch(() => {});
              fetchIncidents().then(setIncidents).catch(() => {});
            } else if (msgType === 'INCIDENT_UPDATED') {
              fetchIncidents().then(setIncidents).catch(() => {});
              fetchStats().then(setStats).catch(() => {});
              if (
                selectedIncidentRef.current &&
                (selectedIncidentRef.current.id === data.id || selectedIncidentRef.current.id === data.incident_id)
              ) {
                const targetId = data.id || data.incident_id;
                fetchIncidentDetail(targetId).then(setSelectedIncident).catch(() => {});
              }
            } else if (msgType === 'AI_ANALYSIS_COMPLETED') {
              fetchIncidents().then(setIncidents).catch(() => {});
              if (selectedIncidentRef.current && selectedIncidentRef.current.id === data.incident_id) {
                fetchIncidentDetail(data.incident_id).then(setSelectedIncident).catch(() => {});
              }
            } else if (
              msgType === 'SEED_COMPLETED' ||
              msgType === 'SIMULATION_COMPLETED' ||
              msgType === 'DATABASE_RESET' ||
              msgType === 'AGENT_REGISTERED' ||
              msgType === 'AGENT_HEARTBEAT' ||
              msgType === 'STATS_UPDATED'
            ) {
              loadData();
            }
          } catch (e) {
            // non-json ping/pong
          }
        };

        socket.onclose = () => {
          setWsConnected(false);
          if (pingInterval) clearInterval(pingInterval);
          if (!isUnmounted) {
            if (reconnectTimeout) clearTimeout(reconnectTimeout);
            reconnectTimeout = setTimeout(connectWs, 2000);
          }
        };

        socket.onerror = () => {
          setWsConnected(false);
        };
      } catch (err) {
        setWsConnected(false);
        if (!isUnmounted) {
          if (reconnectTimeout) clearTimeout(reconnectTimeout);
          reconnectTimeout = setTimeout(connectWs, 2000);
        }
      }
    };

    connectWs();

    return () => {
      isUnmounted = true;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (pingInterval) clearInterval(pingInterval);
      if (socket) {
        socket.close();
      }
    };
  }, [loadData]);

  // Toast Auto-Dismiss
  useEffect(() => {
    if (toastMessage) {
      const t = setTimeout(() => setToastMessage(null), 5000);
      return () => clearTimeout(t);
    }
  }, [toastMessage]);

  const handleQuickSimulate = async () => {
    try {
      setIsSimulating(true);
      await seedSampleAttack();
      await loadData();
      setToastMessage({
        title: 'Attack Chain Simulation Injected',
        desc: '5-stage intrusion sequence correlated into active incident.',
        type: 'success',
      });
      setActiveTab('incidents');
    } catch (err: any) {
      console.error('Quick simulation error:', err);
    } finally {
      setIsSimulating(false);
    }
  };

  const handleSelectIncident = async (inc: Incident) => {
    try {
      const full = await fetchIncidentDetail(inc.id);
      setSelectedIncident(full);
    } catch (err) {
      setSelectedIncident(inc);
    }
  };

  const handleIncidentUpdated = (updated: Incident) => {
    setSelectedIncident(updated);
    setIncidents((prev) => prev.map((i) => (i.id === updated.id ? { ...i, ...updated } : i)));
    fetchStats().then(setStats).catch(() => {});
  };

  const handleFilterAgentLogs = (hostname: string) => {
    setLogHostFilter(hostname);
    setActiveTab('logs');
  };

  const onlineAgentCount = agents.filter((a) => a.status === 'ONLINE').length;
  const filteredLogs = logHostFilter ? logs.filter((l) => l.hostname === logHostFilter) : logs;

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={(tab) => {
          if (tab !== 'logs') setLogHostFilter(null);
          setActiveTab(tab);
        }}
        wsConnected={wsConnected}
        onQuickSimulate={handleQuickSimulate}
        isSimulating={isSimulating}
        onlineAgentCount={onlineAgentCount}
      />

      {/* Main App Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Real-Time Live Security Alert Toast */}
        {toastMessage && (
          <div
            className={`fixed bottom-6 right-6 z-50 p-4 rounded-xl shadow-2xl border flex items-start gap-3 max-w-md transition-all ${
              toastMessage.type === 'alert'
                ? 'bg-rose-950/95 border-rose-700/80 text-white'
                : 'bg-emerald-950/95 border-emerald-700/80 text-white'
            }`}
          >
            {toastMessage.type === 'alert' ? (
              <BellRing className="w-5 h-5 text-rose-400 shrink-0 mt-0.5 animate-bounce" />
            ) : (
              <CheckCircle className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
            )}
            <div className="flex-1 text-xs">
              <div className="font-bold text-sm tracking-tight">{toastMessage.title}</div>
              <div className="text-slate-300 mt-0.5">{toastMessage.desc}</div>
            </div>
            <button
              onClick={() => setToastMessage(null)}
              className="text-slate-400 hover:text-white text-xs font-bold"
            >
              &times;
            </button>
          </div>
        )}

        {/* View 1: SOC Dashboard & Analytics */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            {/* KPI Cards */}
            <StatCards stats={stats} loading={loading} />

            {/* Visual Recharts Area and Bar */}
            <ChartsView stats={stats} />

            {/* Active Incidents Overview */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-base font-bold text-white tracking-tight">Active Security Incidents</h3>
                  <p className="text-xs text-slate-400">
                    Correlated multi-vector attacks triaged by deterministic engine and AI
                  </p>
                </div>
                <button
                  onClick={() => setActiveTab('incidents')}
                  className="text-xs font-semibold text-cyan-400 hover:text-cyan-300 transition"
                >
                  View All Incidents &rarr;
                </button>
              </div>

              <IncidentsTable
                incidents={incidents.slice(0, 5)}
                loading={loading}
                onSelectIncident={handleSelectIncident}
              />
            </div>
          </div>
        )}

        {/* View 2: Agents & Endpoints Management */}
        {activeTab === 'agents' && (
          <AgentsManager
            agents={agents}
            onRefresh={loadData}
            loading={loading}
            onFilterAgentLogs={handleFilterAgentLogs}
          />
        )}

        {/* View 3: Incidents & Deep Triage */}
        {activeTab === 'incidents' && (
          <div className="space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div>
                <h2 className="text-lg font-bold text-white tracking-tight">Incident Response & Triage Enclave</h2>
                <p className="text-xs text-slate-400">
                  Inspect correlated attack graphs, evaluate deterministic risk scores, and run read-only AI investigation
                </p>
              </div>
            </div>

            <IncidentsTable
              incidents={incidents}
              loading={loading}
              onSelectIncident={handleSelectIncident}
            />
          </div>
        )}

        {/* View 4: Live Telemetry Stream */}
        {activeTab === 'logs' && (
          <div className="space-y-3">
            {logHostFilter && (
              <div className="p-3 bg-cyan-950/40 border border-cyan-800/60 rounded-xl flex items-center justify-between text-xs text-cyan-300">
                <span>
                  Filtering telemetry events for host: <strong className="font-mono text-white">{logHostFilter}</strong>
                </span>
                <button
                  onClick={() => setLogHostFilter(null)}
                  className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium"
                >
                  Clear Filter
                </button>
              </div>
            )}
            <LiveLogStream logs={filteredLogs} onRefresh={loadData} loading={loading} />
          </div>
        )}

        {/* View 5: Attack Simulator */}
        {activeTab === 'simulator' && (
          <AttackSimulator onSimulationCompleted={loadData} />
        )}

        {/* View 6: MITRE & Detection Rules Catalog */}
        {activeTab === 'rules' && <RulesAndMitreView />}
      </main>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <IncidentDetailModal
          incident={selectedIncident}
          onClose={() => setSelectedIncident(null)}
          onIncidentUpdated={handleIncidentUpdated}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 text-center text-xs text-slate-500 font-mono">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>AI-SOC &bull; Automated Security Incident Detection, Correlation, and Analysis Framework</span>
          <span className="text-slate-600">Pure Read-Only AI Security Model &bull; Real-Time Telemetry Bus</span>
        </div>
      </footer>
    </div>
  );
}
