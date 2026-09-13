import React, { useState, useEffect } from 'react';
import { BookOpen, ShieldCheck, Cpu, Code2, AlertTriangle, CheckCircle } from 'lucide-react';
import { DetectionRule, MitreTechnique } from '../types';
import { fetchRules, fetchMitreCatalog } from '../services/api';

export const RulesAndMitreView: React.FC = () => {
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [mitreList, setMitreList] = useState<MitreTechnique[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const [r, m] = await Promise.all([fetchRules(), fetchMitreCatalog()]);
        setRules(r);
        setMitreList(m);
      } catch (err) {
        console.error('Failed to load rules and MITRE catalog:', err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const severityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-500/20 text-rose-300 border-rose-500/40';
      case 'HIGH':
        return 'bg-orange-500/20 text-orange-300 border-orange-500/40';
      case 'MEDIUM':
        return 'bg-amber-500/20 text-amber-300 border-amber-500/40';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const ruleDescriptions: Record<string, string> = {
    'RULE-001': 'Aggregates failed SSH authentication attempts from a single source IP over a 5-minute sliding window. Triggers an alert when count exceeds 5.',
    'RULE-002': 'Monitors for successful SSH authentication events originating from an IP address that previously generated 3+ failed logins within the prior 30 minutes.',
    'RULE-003': 'Inspects privilege escalation commands, detecting interactive shell spawns (sudo bash, sudo sh, sudo su, or scripting language wrappers).',
    'RULE-004': 'Analyzes parent-child process relationships for web daemons (nginx, apache2, php-fpm) spawning interactive command shells or download utilities.',
    'RULE-005': 'Inspects outbound network connections to high-risk C2 and reverse shell ports (4444, 1337, 6667, 8888, 9001) and command execution piping.',
  };

  return (
    <div className="space-y-6">
      {/* 1. Monolithic Hybrid Architecture Blueprint Card */}
      <div className="p-6 rounded-2xl bg-slate-900 border border-slate-800">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2 rounded-lg bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">
              Hybrid Rule-Based + LLM Detection & Triage Architecture
            </h2>
            <p className="text-xs text-slate-400">Academic Project Framework Design & Safeguards</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4 text-xs text-slate-300">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <h4 className="font-bold text-cyan-400">1. Fast Deterministic Engine</h4>
            <p className="text-slate-400 leading-relaxed">
              Rules process incoming telemetry with O(1) / indexed lookups, zero hallucination, and immediate threshold triggers for high-frequency attacks.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <h4 className="font-bold text-cyan-400">2. Asset & Identity Correlation</h4>
            <p className="text-slate-400 leading-relaxed">
              Collapses multi-alert noise across hostnames, IPs, and users into a unified Incident model with an explainable 0–100 risk score.
            </p>
          </div>
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5">
            <h4 className="font-bold text-cyan-400">3. Read-Only AI Analyst (Gemini & Qwen)</h4>
            <p className="text-slate-400 leading-relaxed">
              LLMs receive structured JSON graphs and produce summaries, progressions, and containment checklists without execution rights.
            </p>
          </div>
        </div>
      </div>

      {/* 2. Registered Detection Rules */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6">
        <div className="mb-4">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-cyan-400" />
            Registered Detection Engine Rules ({rules.length})
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Modular detection rules implementing the BaseRule contract with deterministic evaluations.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {rules.map((rule) => (
            <div key={rule.rule_id} className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-cyan-400">{rule.rule_id}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${severityBadge(rule.severity)}`}>
                  {rule.severity}
                </span>
              </div>
              <h4 className="font-bold text-sm text-white">{rule.rule_name}</h4>
              <p className="text-xs text-slate-300">{ruleDescriptions[rule.rule_id] || 'Active detection rule.'}</p>
              <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px]">
                <span className="text-slate-400">MITRE Technique:</span>
                <span className="font-mono text-cyan-300 font-semibold">
                  {rule.mitre_technique_id} ({rule.mitre_technique_name})
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* 3. MITRE ATT&CK Matrix Catalog */}
      <div className="rounded-2xl bg-slate-900 border border-slate-800 p-6">
        <div className="mb-4">
          <h3 className="text-base font-bold text-white flex items-center gap-2">
            <BookOpen className="w-5 h-5 text-cyan-400" />
            MITRE ATT&CK Enterprise Matrix Mapping
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Tactics and technique IDs referenced across the AI-SOC detection rules.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {mitreList.map((m) => (
            <div key={m.id} className="p-3.5 rounded-xl bg-slate-950 border border-slate-800 space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-cyan-400">{m.id}</span>
                <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-[10px] text-slate-300 uppercase">
                  {m.tactic}
                </span>
              </div>
              <div className="font-semibold text-white">{m.name}</div>
              <p className="text-slate-400 text-[11px] leading-relaxed">{m.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
