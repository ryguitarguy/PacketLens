import React from 'react';
import { 
  KeyRound, 
  AlertTriangle, 
  Activity, 
  Network, 
  Clock, 
  HardDrive
} from 'lucide-react';
import { TrafficStats, CleartextItem, SecurityAnomaly } from '../types';

interface SummaryCardsProps {
  stats: TrafficStats;
  cleartextItems: CleartextItem[];
  anomalies: SecurityAnomaly[];
  onTabChange: (tab: 'unencrypted' | 'anomalies' | 'traffic' | 'packets') => void;
}

export const SummaryCards: React.FC<SummaryCardsProps> = ({
  stats,
  cleartextItems,
  anomalies,
  onTabChange,
}) => {
  const criticalCredsCount = cleartextItems.filter(i => i.riskLevel === 'critical').length;
  const criticalAnomaliesCount = anomalies.filter(a => a.severity === 'critical').length;

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  const protocolList = Object.keys(stats.protocolCounts).slice(0, 4);

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
      
      {/* 1. Unencrypted Secrets Card */}
      <div 
        id="card-summary-cleartext"
        onClick={() => onTabChange('unencrypted')}
        className="bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-amber-500/40 rounded-xl p-4 transition-all cursor-pointer group shadow-sm"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Unencrypted Findings
          </span>
          <div className="w-8 h-8 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 group-hover:scale-110 transition-transform">
            <KeyRound className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold text-white font-mono">
            {cleartextItems.length}
          </span>
          <span className="text-xs text-slate-400">items harvested</span>
        </div>

        <div className="mt-3 flex items-center gap-1.5 text-xs">
          {criticalCredsCount > 0 ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-400 animate-pulse" />
              {criticalCredsCount} Critical Passwords/Tokens
            </span>
          ) : (
            <span className="text-slate-500">No passwords exposed</span>
          )}
        </div>
      </div>

      {/* 2. Security Anomalies Card */}
      <div 
        id="card-summary-anomalies"
        onClick={() => onTabChange('anomalies')}
        className="bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-rose-500/40 rounded-xl p-4 transition-all cursor-pointer group shadow-sm"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Security Anomalies
          </span>
          <div className="w-8 h-8 rounded-lg bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 group-hover:scale-110 transition-transform">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold text-white font-mono">
            {anomalies.length}
          </span>
          <span className="text-xs text-slate-400">threat indicators</span>
        </div>

        <div className="mt-3 flex items-center gap-1.5 text-xs">
          {criticalAnomaliesCount > 0 ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-rose-500/20 text-rose-300 border border-rose-500/30">
              {criticalAnomaliesCount} Critical Alert{criticalAnomaliesCount > 1 ? 's' : ''}
            </span>
          ) : anomalies.length > 0 ? (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20">
              {anomalies.length} Potential Threats
            </span>
          ) : (
            <span className="text-emerald-400">Baseline clean</span>
          )}
        </div>
      </div>

      {/* 3. Traffic Volume & Packets Card */}
      <div 
        id="card-summary-traffic"
        onClick={() => onTabChange('traffic')}
        className="bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-cyan-500/40 rounded-xl p-4 transition-all cursor-pointer group shadow-sm"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Capture Volume
          </span>
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center text-cyan-400 group-hover:scale-110 transition-transform">
            <HardDrive className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold text-white font-mono">
            {stats.totalPackets.toLocaleString()}
          </span>
          <span className="text-xs text-slate-400 font-mono">
            ({formatBytes(stats.totalBytes)})
          </span>
        </div>

        <div className="mt-3 flex items-center gap-2 text-xs text-slate-400">
          <Clock className="w-3.5 h-3.5 text-slate-500" />
          <span>{stats.durationSeconds}s duration</span>
        </div>
      </div>

      {/* 4. Protocols & Active Hosts Card */}
      <div 
        id="card-summary-protocols"
        onClick={() => onTabChange('packets')}
        className="bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-indigo-500/40 rounded-xl p-4 transition-all cursor-pointer group shadow-sm"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Network Surface
          </span>
          <div className="w-8 h-8 rounded-lg bg-indigo-500/10 border border-indigo-500/20 flex items-center justify-center text-indigo-400 group-hover:scale-110 transition-transform">
            <Network className="w-4 h-4" />
          </div>
        </div>

        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-bold text-white font-mono">
            {stats.topTalkers.length}
          </span>
          <span className="text-xs text-slate-400">active hosts</span>
        </div>

        <div className="mt-3 flex items-center gap-1.5 flex-wrap">
          {protocolList.map(proto => (
            <span 
              key={proto}
              className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300 border border-slate-700"
            >
              {proto}
            </span>
          ))}
        </div>
      </div>

    </div>
  );
};
