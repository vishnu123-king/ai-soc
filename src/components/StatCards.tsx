import React from 'react';
import { ShieldCheck, AlertOctagon, Bell, Database, Cpu } from 'lucide-react';
import { DashboardStats } from '../types';

interface StatCardsProps {
  stats: DashboardStats | null;
  loading: boolean;
}

export const StatCards: React.FC<StatCardsProps> = ({ stats, loading }) => {
  if (loading || !stats) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {[1, 2, 3, 4].map((i) => (
          <div key={i} className="h-28 rounded-xl bg-slate-900/60 border border-slate-800 animate-pulse" />
        ))}
      </div>
    );
  }

  const score = stats.security_score;
  const scoreColor =
    score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : 'text-rose-400';
  const scoreBadgeBg =
    score >= 80 ? 'bg-emerald-950/40 border-emerald-800/60' : score >= 60 ? 'bg-amber-950/40 border-amber-800/60' : 'bg-rose-950/40 border-rose-800/60';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      {/* 1. Security Posture Score */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Security Posture</span>
          <div className={`p-1.5 rounded-lg ${scoreBadgeBg} border`}>
            <ShieldCheck className={`w-4 h-4 ${scoreColor}`} />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className={`text-3xl font-extrabold ${scoreColor}`}>{score}</span>
          <span className="text-xs text-slate-500 font-mono">/ 100</span>
        </div>
        <div className="mt-3 w-full bg-slate-800 h-1.5 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all duration-700 ${
              score >= 80 ? 'bg-emerald-500' : score >= 60 ? 'bg-amber-500' : 'bg-rose-500'
            }`}
            style={{ width: `${score}%` }}
          />
        </div>
        <p className="mt-2 text-xs text-slate-400 flex items-center justify-between">
          <span>Target: &gt;85</span>
          <span className="font-semibold text-slate-300">
            {stats.critical_incidents > 0 ? `${stats.critical_incidents} Critical Threat Active` : 'Posture Normal'}
          </span>
        </p>
      </div>

      {/* 2. Active Incidents */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Active Incidents</span>
          <div className="p-1.5 rounded-lg bg-rose-950/40 border border-rose-800/60">
            <AlertOctagon className="w-4 h-4 text-rose-400" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white">{stats.active_incidents}</span>
          <span className="text-xs text-slate-400 font-mono">Correlated Clusters</span>
        </div>
        <div className="mt-2.5 flex items-center gap-1.5 text-xs">
          <span className="px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 font-medium">
            {stats.critical_incidents} Critical
          </span>
          <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 font-medium">
            {stats.high_incidents} High
          </span>
          <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400">
            {stats.medium_incidents} Medium
          </span>
        </div>
      </div>

      {/* 3. Correlated Alerts */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Rule Alerts Fired</span>
          <div className="p-1.5 rounded-lg bg-cyan-950/40 border border-cyan-800/60">
            <Bell className="w-4 h-4 text-cyan-400" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white">{stats.total_alerts}</span>
          <span className="text-xs text-slate-400 font-mono">MITRE Detections</span>
        </div>
        <p className="mt-2 text-xs text-slate-400">
          5 Core heuristic engines active with deterministic signature matching.
        </p>
      </div>

      {/* 4. Total Ingested Events */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Ingested Logs</span>
          <div className="p-1.5 rounded-lg bg-indigo-950/40 border border-indigo-800/60">
            <Database className="w-4 h-4 text-indigo-400" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-extrabold text-white">{stats.total_events}</span>
          <span className="text-xs text-slate-400 font-mono">Normalized</span>
        </div>
        <p className="mt-2 text-xs text-slate-400 flex items-center gap-1.5">
          <Cpu className="w-3.5 h-3.5 text-cyan-400" />
          <span>Sub-millisecond processing latency</span>
        </p>
      </div>
    </div>
  );
};
