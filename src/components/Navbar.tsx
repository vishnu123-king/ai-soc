import React from 'react';
import { Shield, Radio, Terminal, AlertTriangle, Zap, FileText, BookOpen, Layers } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  wsConnected: boolean;
  onQuickSimulate: () => void;
  isSimulating: boolean;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  wsConnected,
  onQuickSimulate,
  isSimulating,
}) => {
  const tabs = [
    { id: 'dashboard', label: 'SOC Dashboard', icon: Layers },
    { id: 'incidents', label: 'Incidents & Triage', icon: AlertTriangle },
    { id: 'logs', label: 'Live Telemetry Stream', icon: Terminal },
    { id: 'simulator', label: 'Attack Simulator', icon: Zap },
    { id: 'rules', label: 'MITRE & Detection Rules', icon: BookOpen },
  ];

  return (
    <header className="sticky top-0 z-40 bg-slate-900/95 backdrop-blur border-b border-slate-800 text-slate-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand */}
          <div className="flex items-center gap-3 cursor-pointer" onClick={() => setActiveTab('dashboard')}>
            <div className="w-10 h-10 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shadow-sm">
              <Shield className="w-6 h-6 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white">AI-SOC</span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-mono">
                  v1.0 MONOLITH
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Hybrid Rule-Based & Local/Cloud LLM Detection Framework
              </p>
            </div>
          </div>

          {/* Navigation Tabs */}
          <nav className="hidden md:flex items-center space-x-1">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  id={`nav-tab-${tab.id}`}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3.5 py-2 rounded-md text-xs font-medium transition-colors ${
                    isActive
                      ? 'bg-slate-800 text-cyan-400 border border-slate-700 shadow-inner'
                      : 'text-slate-300 hover:bg-slate-800/60 hover:text-white'
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                  {tab.label}
                </button>
              );
            })}
          </nav>

          {/* Controls & WebSocket Status */}
          <div className="flex items-center gap-3">
            {/* Live WebSocket indicator */}
            <div
              className={`flex items-center gap-2 px-2.5 py-1 rounded-full text-xs font-mono border ${
                wsConnected
                  ? 'bg-emerald-950/40 text-emerald-400 border-emerald-800/60'
                  : 'bg-amber-950/40 text-amber-400 border-amber-800/60'
              }`}
              title={wsConnected ? 'WebSocket live telemetry streaming connected' : 'Connecting to live telemetry bus...'}
            >
              <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'animate-pulse text-emerald-400' : 'text-amber-400'}`} />
              <span className="hidden sm:inline">{wsConnected ? 'BUS LIVE' : 'CONNECTING'}</span>
            </div>

            {/* Quick Simulate Attack Button */}
            <button
              id="quick-simulate-btn"
              onClick={onQuickSimulate}
              disabled={isSimulating}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-red-500/15 text-red-400 border border-red-500/30 hover:bg-red-500/25 transition-all disabled:opacity-50"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>{isSimulating ? 'Simulating...' : 'Simulate Attack'}</span>
            </button>

            {/* FastAPI Interactive Docs Link */}
            <a
              href="/docs"
              target="_blank"
              rel="noreferrer"
              className="hidden lg:flex items-center gap-1 px-2.5 py-1.5 rounded-md text-xs font-medium text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition"
              title="Open FastAPI Swagger Interactive API Documentation"
            >
              <FileText className="w-3.5 h-3.5" />
              <span>API Docs</span>
            </a>
          </div>
        </div>

        {/* Mobile Sub-Navigation Bar */}
        <div className="flex md:hidden overflow-x-auto py-2 gap-1 border-t border-slate-800">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs whitespace-nowrap ${
                  isActive ? 'bg-slate-800 text-cyan-400 font-semibold' : 'text-slate-400'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                {tab.label}
              </button>
            );
          })}
        </div>
      </div>
    </header>
  );
};
