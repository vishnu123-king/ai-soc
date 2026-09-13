import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Navbar } from './components/Navbar';
import { StatCards } from './components/StatCards';
import { ChartsView } from './components/ChartsView';
import { IncidentsTable } from './components/IncidentsTable';
import { IncidentDetailModal } from './components/IncidentDetailModal';
import { LiveLogStream } from './components/LiveLogStream';
import { AttackSimulator } from './components/AttackSimulator';
import { RulesAndMitreView } from './components/RulesAndMitreView';
import { fetchStats, fetchIncidents, fetchLogs, fetchIncidentDetail, seedSampleAttack } from './services/api';
import { DashboardStats, Incident, SecurityLog, Alert } from './types';
import { AlertOctagon, BellRing, CheckCircle, ExternalLink, Shield } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('dashboard');
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(false);
  const [isSimulating, setIsSimulating] = useState<boolean>(false);
  const [toastMessage, setToastMessage] = useState<{ title: string; desc: string; type: 'alert' | 'success' } | null>(
    null
  );

  const wsRef = useRef<WebSocket | null>(null);

  // Load initial application state
  const loadData = useCallback(async () => {
    try {
      setLoading(true);
      const [st, inc, lg] = await Promise.all([
        fetchStats(),
        fetchIncidents(),
        fetchLogs(80),
      ]);
      setStats(st);
      setIncidents(inc);
      setLogs(lg);
    } catch (err) {
      console.error('Failed to load SOC dashboard telemetry:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // WebSocket Live Security Telemetry Connection
  useEffect(() => {
    let socket: WebSocket | null = null;
    let reconnectTimeout: any = null;

    const connectWs = () => {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/ws`;

      socket = new WebSocket(wsUrl);
      wsRef.current = socket;

      socket.onopen = () => {
        setWsConnected(true);
      };

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const msgType = payload.type;
          const data = payload.data;

          if (msgType === 'NEW_LOG') {
            setLogs((prev) => [
              {
                id: data.id,
                timestamp: data.timestamp,
                hostname: data.hostname,
                event_type: data.event_type,
                status: data.status,
                source_ip: data.source_ip,
                raw_message: `${data.event_type} on ${data.hostname} (${data.status})`,
              },
              ...prev.slice(0, 100),
            ]);
          } else if (msgType === 'NEW_ALERT') {
            setToastMessage({
              title: `Security Alert: ${data.rule_name}`,
              desc: `${data.description} on ${data.hostname}`,
              type: 'alert',
            });
            // Refresh stats
            fetchStats().then(setStats).catch(() => {});
          } else if (msgType === 'INCIDENT_UPDATED') {
            fetchIncidents().then(setIncidents).catch(() => {});
            fetchStats().then(setStats).catch(() => {});
          } else if (msgType === 'AI_ANALYSIS_COMPLETED') {
            fetchIncidents().then(setIncidents).catch(() => {});
            if (selectedIncident && selectedIncident.id === data.incident_id) {
              fetchIncidentDetail(data.incident_id).then(setSelectedIncident).catch(() => {});
            }
          } else if (msgType === 'SEED_COMPLETED' || msgType === 'DATABASE_RESET') {
            loadData();
          }
        } catch (e) {
          // non-json ping/pong
        }
      };

      socket.onclose = () => {
        setWsConnected(false);
        reconnectTimeout = setTimeout(connectWs, 3000);
      };

      socket.onerror = () => {
        setWsConnected(false);
      };
    };

    connectWs();

    return () => {
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (socket) socket.close();
    };
  }, [loadData, selectedIncident]);

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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Navigation */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        wsConnected={wsConnected}
        onQuickSimulate={handleQuickSimulate}
        isSimulating={isSimulating}
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

        {/* View 2: Incidents & Deep Triage */}
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

        {/* View 3: Live Telemetry Stream */}
        {activeTab === 'logs' && (
          <LiveLogStream logs={logs} onRefresh={loadData} loading={loading} />
        )}

        {/* View 4: Attack Simulator */}
        {activeTab === 'simulator' && (
          <AttackSimulator onSimulationCompleted={loadData} />
        )}

        {/* View 5: MITRE & Detection Rules Catalog */}
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
          <span className="text-slate-600">Pure Read-Only AI Security Model &bull; Modular Monolith Architecture</span>
        </div>
      </footer>
    </div>
  );
}
