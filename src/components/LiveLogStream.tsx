import React, { useState } from 'react';
import { Terminal, Pause, Play, Search, Filter, ArrowDownCircle, RefreshCw } from 'lucide-react';
import { SecurityLog } from '../types';

interface LiveLogStreamProps {
  logs: SecurityLog[];
  onRefresh: () => void;
  loading: boolean;
}

export const LiveLogStream: React.FC<LiveLogStreamProps> = ({ logs, onRefresh, loading }) => {
  const [search, setSearch] = useState('');
  const [eventTypeFilter, setEventTypeFilter] = useState('ALL');
  const [isPaused, setIsPaused] = useState(false);
  const [selectedLog, setSelectedLog] = useState<SecurityLog | null>(null);

  const filteredLogs = logs.filter((log) => {
    const matchSearch =
      log.raw_message.toLowerCase().includes(search.toLowerCase()) ||
      log.hostname.toLowerCase().includes(search.toLowerCase()) ||
      (log.source_ip && log.source_ip.includes(search)) ||
      (log.username && log.username.toLowerCase().includes(search.toLowerCase()));

    const matchType = eventTypeFilter === 'ALL' || log.event_type.toLowerCase() === eventTypeFilter.toLowerCase();
    return matchSearch && matchType;
  });

  return (
    <div className="rounded-xl bg-slate-900 border border-slate-800 overflow-hidden shadow-sm flex flex-col h-[700px]">
      {/* Stream Header & Controls */}
      <div className="p-4 border-b border-slate-800 flex flex-wrap items-center justify-between gap-3 bg-slate-950/70">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Terminal className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-sm font-bold text-white">Live Endpoint Telemetry Stream</h3>
            <p className="text-xs text-slate-400">
              Real-time ingestion & normalization bus ({logs.length} events buffered)
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Pause / Resume */}
          <button
            onClick={() => setIsPaused(!isPaused)}
            className={`flex items-center gap-1.5 px-3 py-1 rounded-md text-xs font-semibold border transition ${
              isPaused
                ? 'bg-amber-500/20 text-amber-300 border-amber-500/40'
                : 'bg-slate-800 text-slate-300 border-slate-700 hover:bg-slate-700'
            }`}
          >
            {isPaused ? <Play className="w-3 h-3" /> : <Pause className="w-3 h-3" />}
            <span>{isPaused ? 'Resume Stream' : 'Pause'}</span>
          </button>

          {/* Refresh */}
          <button
            onClick={onRefresh}
            disabled={loading}
            className="p-1.5 rounded-md bg-slate-800 text-slate-400 hover:text-white border border-slate-700 transition"
            title="Refresh logs from database"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
        </div>
      </div>

      {/* Filter Bar */}
      <div className="p-3 border-b border-slate-800 bg-slate-950/40 flex flex-col sm:flex-row items-center gap-3">
        <div className="relative flex-1 w-full">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search raw syslog messages, processes, IPs, users..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1 rounded bg-slate-900 border border-slate-800 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-1.5 text-xs text-slate-400 w-full sm:w-auto">
          <Filter className="w-3 h-3" />
          <select
            value={eventTypeFilter}
            onChange={(e) => setEventTypeFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 rounded px-2 py-1 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Event Types</option>
            <option value="auth">Auth / SSH</option>
            <option value="process">Process Exec</option>
            <option value="privilege">Privilege / Sudo</option>
            <option value="network">Network Socket</option>
          </select>
        </div>
      </div>

      {/* Main Terminal-Style Log Table */}
      <div className="flex-1 overflow-y-auto font-mono text-xs divide-y divide-slate-800/60 bg-slate-950">
        {filteredLogs.length === 0 ? (
          <div className="p-8 text-center text-slate-500 font-sans text-xs">
            No telemetry matching filters.
          </div>
        ) : (
          filteredLogs.map((log) => {
            const isFailure = log.status === 'failure' || log.status === 'denied';
            return (
              <div
                key={log.id}
                onClick={() => setSelectedLog(selectedLog?.id === log.id ? null : log)}
                className={`p-2.5 hover:bg-slate-800/40 cursor-pointer flex flex-col gap-1 transition ${
                  selectedLog?.id === log.id ? 'bg-slate-800/50' : ''
                }`}
              >
                <div className="flex items-center justify-between text-[11px]">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-500 font-mono">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className="px-1.5 py-0.2 rounded bg-slate-800 text-cyan-400 text-[10px]">
                      {log.hostname}
                    </span>
                    <span
                      className={`px-1.5 py-0.2 rounded text-[10px] uppercase font-semibold ${
                        isFailure ? 'bg-rose-950/80 text-rose-400' : 'bg-emerald-950/80 text-emerald-400'
                      }`}
                    >
                      {log.event_type} &bull; {log.status}
                    </span>
                    {log.username && <span className="text-slate-400">user:{log.username}</span>}
                  </div>
                  {log.source_ip && (
                    <span className="text-slate-500 text-[10px]">src:{log.source_ip}</span>
                  )}
                </div>

                {/* Message / Command */}
                <div className="text-slate-300 break-all text-xs pl-2 border-l-2 border-slate-700">
                  {log.command ? (
                    <span className="text-amber-300">
                      $ {log.command} <span className="text-slate-500 font-normal">({log.raw_message})</span>
                    </span>
                  ) : (
                    log.raw_message
                  )}
                </div>

                {/* Detailed JSON Drawer on Click */}
                {selectedLog?.id === log.id && (
                  <div className="mt-2 p-2.5 rounded bg-slate-900 border border-slate-700/80 text-[11px] text-cyan-300">
                    <span className="text-slate-400 block mb-1">Normalized Schema Representation:</span>
                    <pre className="overflow-x-auto">{JSON.stringify(log, null, 2)}</pre>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
