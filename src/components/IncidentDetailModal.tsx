import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Bot,
  FileCheck,
  CheckCircle2,
  AlertCircle,
  Clock,
  Laptop,
  Globe,
  User,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Sparkles,
  ArrowRight,
  Printer,
} from 'lucide-react';
import { Incident, Severity, IncidentStatus } from '../types';
import { updateIncidentStatus, triggerAIAnalysis } from '../services/api';

interface IncidentDetailModalProps {
  incident: Incident | null;
  onClose: () => void;
  onIncidentUpdated: (updated: Incident) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onIncidentUpdated,
}) => {
  const [selectedProvider, setSelectedProvider] = useState<'gemini' | 'local_qwen'>('gemini');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [statusUpdating, setStatusUpdating] = useState(false);
  const [expandedAlerts, setExpandedAlerts] = useState<Record<number, boolean>>({});

  if (!incident) return null;

  const toggleAlertExpand = (alertId: number) => {
    setExpandedAlerts((prev) => ({ ...prev, [alertId]: !prev[alertId] }));
  };

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    try {
      setStatusUpdating(true);
      const updated = await updateIncidentStatus(incident.id, newStatus);
      onIncidentUpdated({ ...incident, status: updated.status });
    } catch (err) {
      console.error('Failed to update incident status:', err);
    } finally {
      setStatusUpdating(false);
    }
  };

  const handleRunAI = async () => {
    try {
      setIsAnalyzing(true);
      const analysis = await triggerAIAnalysis(incident.id, selectedProvider);
      onIncidentUpdated({
        ...incident,
        ai_analysis: analysis,
        ai_model_used: analysis.model_provider,
        ai_analyzed_at: new Date().toISOString(),
      });
    } catch (err) {
      console.error('AI Analysis failed:', err);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const severityBadgeClass = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      case 'LOW':
        return 'bg-sky-500/20 text-sky-300 border-sky-500/40';
      default:
        return 'bg-slate-700 text-slate-300 border-slate-600';
    }
  };

  const score = incident.risk_score;
  const scoreColor = score >= 80 ? 'text-rose-400' : score >= 60 ? 'text-orange-400' : 'text-amber-400';

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-950/80 backdrop-blur-sm flex justify-center p-3 sm:p-6">
      <div className="relative w-full max-w-5xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col my-auto max-h-[92vh]">
        {/* Top Header */}
        <div className="p-6 border-b border-slate-800 flex items-start justify-between bg-slate-900/90 sticky top-0 z-10 backdrop-blur">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <span className={`px-2.5 py-0.5 rounded-md text-xs font-bold border ${severityBadgeClass(incident.severity)}`}>
                {incident.severity}
              </span>
              <span className="text-xs font-mono text-slate-400">INC-{incident.id}</span>
              <span className="text-xs text-slate-500">•</span>
              <div className="flex items-center gap-1.5 text-xs text-slate-400">
                <Clock className="w-3.5 h-3.5" />
                <span>{new Date(incident.created_at).toLocaleString()}</span>
              </div>
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight">{incident.title}</h2>
          </div>

          <div className="flex items-center gap-3">
            {/* HTML Report Link */}
            <a
              href={`/api/incidents/${incident.id}/report`}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-cyan-400 border border-slate-700 transition"
              title="Generate printable formal HTML audit report"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print Report</span>
              <ExternalLink className="w-3 h-3 text-slate-400" />
            </a>

            {/* Close */}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-6 space-y-6 overflow-y-auto">
          {/* Metadata & Risk Score Overview Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Host & Asset Details */}
            <div className="md:col-span-2 p-4 rounded-xl bg-slate-950/60 border border-slate-800 space-y-3">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Asset & Threat Actor Telemetry
              </span>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-4 text-xs">
                <div>
                  <div className="flex items-center gap-1 text-slate-400 mb-1">
                    <Laptop className="w-3.5 h-3.5" /> Affected Host
                  </div>
                  <span className="font-mono font-medium text-slate-200">{incident.affected_host || (incident as any).hostname || 'N/A'}</span>
                </div>
                <div>
                  <div className="flex items-center gap-1 text-slate-400 mb-1">
                    <Globe className="w-3.5 h-3.5" /> Source IP
                  </div>
                  <span className="font-mono font-medium text-rose-400">{incident.source_ip || 'N/A'}</span>
                </div>
                <div>
                  <div className="flex items-center gap-1 text-slate-400 mb-1">
                    <User className="w-3.5 h-3.5" /> Impacted User
                  </div>
                  <span className="font-mono font-medium text-slate-200">{incident.username || 'System'}</span>
                </div>
              </div>

              {/* Status Selector */}
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between">
                <span className="text-xs text-slate-400">Incident Triage Status:</span>
                <div className="flex items-center gap-1">
                  {(['OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED'] as IncidentStatus[]).map((st) => {
                    const isSelected =
                      incident.status === st ||
                      (st === 'OPEN' && incident.status === 'NEW') ||
                      (st === 'CLOSED' && (incident.status === 'RESOLVED' || incident.status === 'FALSE_POSITIVE'));
                    return (
                      <button
                        key={st}
                        disabled={statusUpdating}
                        onClick={() => handleStatusChange(st)}
                        className={`px-2.5 py-1 rounded text-xs font-semibold transition ${
                          isSelected
                            ? 'bg-cyan-500 text-slate-950 font-bold shadow-sm'
                            : 'bg-slate-800 text-slate-400 hover:text-white hover:bg-slate-700'
                        }`}
                      >
                        {st}
                      </button>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Risk Score Card */}
            <div className="p-4 rounded-xl bg-slate-950/60 border border-slate-800 flex flex-col justify-between">
              <div>
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                  Deterministic Risk Score
                </span>
                <div className="flex items-baseline gap-2 mt-2">
                  <span className={`text-4xl font-black ${scoreColor}`}>{incident.risk_score}</span>
                  <span className="text-sm text-slate-500 font-mono">/ 100</span>
                </div>
              </div>
              <p className="text-xs text-slate-400 mt-2 line-clamp-3">{incident.risk_explanation}</p>
            </div>
          </div>

          {/* MITRE ATT&CK Badges */}
          <div>
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block mb-2">
              Mapped MITRE ATT&CK Techniques ({incident.mitre_techniques?.length || 0})
            </span>
            <div className="flex flex-wrap gap-2">
              {incident.mitre_techniques && incident.mitre_techniques.length > 0 ? (
                incident.mitre_techniques.map((tech) => (
                  <div
                    key={tech.id}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800/80 border border-slate-700 text-xs"
                  >
                    <span className="font-mono font-bold text-cyan-400">{tech.id}</span>
                    <span className="text-slate-200">{tech.name}</span>
                    <span className="text-slate-500 text-[10px] px-1.5 py-0.5 rounded bg-slate-900 uppercase">
                      {tech.tactic}
                    </span>
                  </div>
                ))
              ) : (
                <span className="text-xs text-slate-500">No techniques explicitly mapped.</span>
              )}
            </div>
          </div>

          {/* AI Security Analyst Section */}
          <div className="rounded-xl border border-slate-700/80 bg-gradient-to-b from-slate-900 to-slate-950 p-5 space-y-4 shadow-md">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
                  <Bot className="w-5 h-5" />
                </div>
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2">
                    AI Security Analyst
                    <span className="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800/60 font-normal">
                      Read-Only Enclave
                    </span>
                  </h3>
                  <p className="text-xs text-slate-400">
                    Automated Tier-3 incident response triage & MITRE attack correlation
                  </p>
                </div>
              </div>

              {/* Provider Selection & Run Button */}
              <div className="flex items-center gap-2">
                <select
                  value={selectedProvider}
                  onChange={(e) => setSelectedProvider(e.target.value as any)}
                  className="bg-slate-800 text-slate-200 text-xs rounded-lg px-2.5 py-1.5 border border-slate-700 focus:outline-none focus:border-cyan-500"
                >
                  <option value="gemini">Google Gemini 2.5 Flash</option>
                  <option value="local_qwen">Local LLM (Qwen2.5)</option>
                </select>

                <button
                  id="run-ai-analysis-btn"
                  onClick={handleRunAI}
                  disabled={isAnalyzing}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-cyan-500 hover:bg-cyan-400 text-slate-950 transition disabled:opacity-50"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>{isAnalyzing ? 'Analyzing...' : 'Run Analysis'}</span>
                </button>
              </div>
            </div>

            {/* AI Analysis Display */}
            {incident.ai_analysis ? (
              <div className="space-y-4 pt-1">
                {/* Taxonomy & Model info */}
                <div className="flex flex-wrap items-center justify-between gap-2 p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs">
                  <div>
                    <span className="text-slate-400">Likely Attack Taxonomy: </span>
                    <strong className="text-cyan-300 font-semibold">{incident.ai_analysis.likely_attack_type}</strong>
                  </div>
                  <div className="flex items-center gap-3">
                    <span className="text-slate-400">
                      Confidence:{' '}
                      <strong className="text-emerald-400">
                        {Math.round((incident.ai_analysis.confidence || 0.95) * 100)}%
                      </strong>
                    </span>
                    <span className="text-slate-500 font-mono text-[11px]">
                      via {incident.ai_model_used || 'Gemini'}
                    </span>
                  </div>
                </div>

                {/* Executive Summary */}
                <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80">
                  <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-1">
                    Executive & Technical Summary
                  </h4>
                  <p className="text-xs text-slate-300 leading-relaxed">{incident.ai_analysis.incident_summary}</p>
                </div>

                {/* Two Column: Attack Progression & Verified Evidence */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  {/* Progression */}
                  <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <ArrowRight className="w-3.5 h-3.5 text-cyan-400" />
                      Hypothesized Attack Progression
                    </h4>
                    <ol className="space-y-2 text-xs text-slate-300">
                      {incident.ai_analysis.attack_progression.map((step, idx) => (
                        <li key={idx} className="flex gap-2">
                          <span className="font-bold text-cyan-400">{idx + 1}.</span>
                          <span>{step}</span>
                        </li>
                      ))}
                    </ol>
                  </div>

                  {/* Verified Evidence (Strict Anti-Hallucination) */}
                  <div className="p-4 rounded-lg bg-slate-950/80 border border-slate-800/80">
                    <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <FileCheck className="w-3.5 h-3.5 text-emerald-400" />
                      Correlated Telemetry Evidence (Verified)
                    </h4>
                    <ul className="space-y-1.5 text-xs font-mono text-slate-300">
                      {incident.ai_analysis.evidence.map((ev, idx) => (
                        <li key={idx} className="p-1.5 rounded bg-slate-900 border border-slate-800 text-[11px] truncate">
                          {ev}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Recommendations */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-4 rounded-lg bg-slate-950/80 border border-cyan-950">
                    <h4 className="text-xs font-semibold text-cyan-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
                      Recommended Investigation Procedures
                    </h4>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {incident.ai_analysis.recommended_investigation_steps.map((st, idx) => (
                        <li key={idx} className="flex items-start gap-1.5">
                          <span className="text-cyan-500 font-bold">•</span>
                          <span>{st}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-4 rounded-lg bg-slate-950/80 border border-rose-950">
                    <h4 className="text-xs font-semibold text-rose-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                      <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
                      Containment & Remediation Checklist
                    </h4>
                    <ul className="space-y-1.5 text-xs text-slate-300">
                      {incident.ai_analysis.recommended_containment_steps.map((st, idx) => (
                        <li key={idx} className="flex items-start gap-1.5">
                          <span className="text-rose-500 font-bold">•</span>
                          <span>{st}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-8 text-center bg-slate-950/40 rounded-lg border border-dashed border-slate-800">
                <Bot className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <p className="text-sm font-medium text-slate-300">AI Analysis Not Yet Triggered</p>
                <p className="text-xs text-slate-500 max-w-sm mx-auto mt-1">
                  Click 'Run Analysis' to have Gemini or Local Qwen evaluate the telemetry graph.
                </p>
              </div>
            )}
          </div>

          {/* Correlated Alerts Table with Collapsible Evidence */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Correlated Detection Alerts ({incident.alerts?.length || 0})
              </span>
            </div>

            <div className="rounded-xl border border-slate-800 overflow-hidden">
              <div className="divide-y divide-slate-800">
                {incident.alerts && incident.alerts.length > 0 ? (
                  incident.alerts.map((alert) => {
                    const isExpanded = !!expandedAlerts[alert.id];
                    return (
                      <div key={alert.id} className="bg-slate-950/40 hover:bg-slate-800/40 transition">
                        <div
                          className="p-3.5 flex items-center justify-between cursor-pointer"
                          onClick={() => toggleAlertExpand(alert.id)}
                        >
                          <div className="flex items-center gap-3">
                            <button className="text-slate-500 hover:text-slate-300">
                              {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                            </button>
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold border ${severityBadgeClass(
                                alert.severity
                              )}`}
                            >
                              {alert.severity}
                            </span>
                            <div>
                              <div className="font-semibold text-xs text-white flex items-center gap-2">
                                <span>{alert.rule_name}</span>
                                {alert.mitre_technique_id && (
                                  <span className="font-mono text-cyan-400 text-[11px]">
                                    [{alert.mitre_technique_id}]
                                  </span>
                                )}
                              </div>
                              <div className="text-xs text-slate-400 mt-0.5">{alert.description}</div>
                            </div>
                          </div>
                          <span className="text-[11px] font-mono text-slate-500 whitespace-nowrap">
                            {new Date(alert.timestamp).toLocaleTimeString()}
                          </span>
                        </div>

                        {/* Expandable Evidence View */}
                        {isExpanded && (
                          <div className="p-3.5 bg-slate-950 border-t border-slate-800/80 text-xs font-mono space-y-2">
                            <span className="text-[11px] text-slate-400 uppercase font-semibold">Raw Evidence Objects:</span>
                            <pre className="p-3 rounded bg-slate-900 border border-slate-800 text-[11px] text-cyan-300 overflow-x-auto">
                              {JSON.stringify(alert.evidence, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    );
                  })
                ) : (
                  <div className="p-6 text-center text-xs text-slate-500">No alerts correlated.</div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
