import React, { useState } from 'react';
import { Search, Filter, ShieldAlert, ChevronRight, ExternalLink, ArrowUpDown } from 'lucide-react';
import { Incident, Severity, IncidentStatus } from '../types';

interface IncidentsTableProps {
  incidents: Incident[];
  loading: boolean;
  onSelectIncident: (incident: Incident) => void;
}

export const IncidentsTable: React.FC<IncidentsTableProps> = ({
  incidents,
  loading,
  onSelectIncident,
}) => {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filtered = incidents.filter((inc) => {
    const matchesSearch =
      inc.title.toLowerCase().includes(search.toLowerCase()) ||
      inc.affected_host.toLowerCase().includes(search.toLowerCase()) ||
      (inc.source_ip && inc.source_ip.toLowerCase().includes(search.toLowerCase()));

    const matchesSeverity = severityFilter === 'ALL' || inc.severity === severityFilter;
    const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter;

    return matchesSearch && matchesSeverity && matchesStatus;
  });

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
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const statusBadgeClass = (status: IncidentStatus) => {
    switch (status) {
      case 'OPEN':
        return 'bg-rose-950/60 text-rose-400 border-rose-800/60';
      case 'INVESTIGATING':
        return 'bg-amber-950/60 text-amber-400 border-amber-800/60';
      case 'CONTAINED':
        return 'bg-blue-950/60 text-blue-400 border-blue-800/60';
      case 'CLOSED':
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm">
      {/* Controls Bar */}
      <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Search */}
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Filter incidents by title, host, or source IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
          />
        </div>

        {/* Filters */}
        <div className="flex items-center gap-2">
          {/* Severity */}
          <div className="flex items-center gap-1.5 text-xs text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              className="bg-slate-950 border border-slate-800 text-slate-200 rounded-md px-2 py-1 text-xs focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Status */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-200 rounded-md px-2 py-1 text-xs focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="CONTAINED">Contained</option>
            <option value="CLOSED">Closed</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-slate-950/60 text-slate-400 uppercase font-mono border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Incident ID & Title</th>
              <th className="py-3 px-4">Affected Asset</th>
              <th className="py-3 px-4">Attacker IP</th>
              <th className="py-3 px-4">Risk Score</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {loading ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500">
                  Loading security incidents...
                </td>
              </tr>
            ) : filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-8 text-center text-slate-500">
                  No security incidents matching filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((inc) => {
                const score = inc.risk_score;
                const scoreColor =
                  score >= 80 ? 'bg-rose-500' : score >= 60 ? 'bg-orange-500' : 'bg-amber-500';

                return (
                  <tr
                    key={inc.id}
                    onClick={() => onSelectIncident(inc)}
                    className="hover:bg-slate-800/40 cursor-pointer transition"
                  >
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${severityBadgeClass(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-white tracking-tight">
                        <span className="font-mono text-cyan-400 mr-2">INC-{inc.id}</span>
                        {inc.title}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5 flex items-center gap-2">
                        <span>{new Date(inc.created_at).toLocaleDateString()}</span>
                        <span>•</span>
                        <span>{inc.alerts?.length || 1} Correlated Alert(s)</span>
                        {inc.ai_model_used && (
                          <>
                            <span>•</span>
                            <span className="text-cyan-400">AI Triaged</span>
                          </>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300 whitespace-nowrap">
                      {inc.affected_host}
                    </td>
                    <td className="py-3 px-4 font-mono text-rose-400 whitespace-nowrap">
                      {inc.source_ip || 'N/A'}
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-2">
                        <div className="w-14 bg-slate-800 h-1.5 rounded-full overflow-hidden">
                          <div className={`h-full ${scoreColor}`} style={{ width: `${score}%` }} />
                        </div>
                        <span className="font-bold text-slate-200">{score}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${statusBadgeClass(inc.status)}`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectIncident(inc);
                        }}
                        className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 text-xs font-medium border border-slate-700 inline-flex items-center gap-1 transition"
                      >
                        <span>Triage</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
