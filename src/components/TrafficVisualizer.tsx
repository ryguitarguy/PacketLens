import React, { useState } from 'react';
import { 
  BarChart3, 
  PieChart, 
  ArrowLeftRight, 
  Activity, 
  Radio, 
  Server,
  Layers
} from 'lucide-react';
import { TrafficStats } from '../types';

interface TrafficVisualizerProps {
  stats: TrafficStats;
  onFilterConversation?: (ipA: string, ipB: string) => void;
}

export const TrafficVisualizer: React.FC<TrafficVisualizerProps> = ({
  stats,
  onFilterConversation,
}) => {
  const [hoveredBucket, setHoveredBucket] = useState<number | null>(null);

  const formatBytes = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  // Find max packets in any bucket for timeline chart scaling
  const maxBucketPackets = Math.max(1, ...stats.timeBuckets.map(b => b.totalPackets));

  const totalPackets = stats.totalPackets || 1;

  // Protocol color map
  const getProtocolColor = (proto: string): { bg: string; text: string; fill: string } => {
    switch (proto) {
      case 'HTTP': return { bg: 'bg-emerald-500', text: 'text-emerald-400', fill: '#10b981' };
      case 'DNS': return { bg: 'bg-cyan-500', text: 'text-cyan-400', fill: '#06b6d4' };
      case 'HTTPS/TLS': return { bg: 'bg-purple-500', text: 'text-purple-400', fill: '#a855f7' };
      case 'TCP': return { bg: 'bg-indigo-500', text: 'text-indigo-400', fill: '#6366f1' };
      case 'UDP': return { bg: 'bg-blue-500', text: 'text-blue-400', fill: '#3b82f6' };
      case 'FTP': return { bg: 'bg-amber-500', text: 'text-amber-400', fill: '#f59e0b' };
      case 'TELNET': return { bg: 'bg-rose-500', text: 'text-rose-400', fill: '#f43f5e' };
      default: return { bg: 'bg-slate-500', text: 'text-slate-400', fill: '#64748b' };
    }
  };

  return (
    <div className="space-y-6">
      
      {/* 1. Interactive Traffic Activity Timeline */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-4">
          <div>
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <span>Packet Capture Activity &amp; Protocol Timeline</span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Traffic rate over time segmented by application protocol
            </p>
          </div>

          {/* Timeline Protocol Legend */}
          <div className="flex items-center gap-3 text-[11px] font-mono flex-wrap">
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-emerald-500" />
              <span className="text-slate-300">HTTP</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-cyan-500" />
              <span className="text-slate-300">DNS</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-purple-500" />
              <span className="text-slate-300">TLS</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-indigo-500" />
              <span className="text-slate-300">TCP</span>
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-sm bg-slate-500" />
              <span className="text-slate-300">Other</span>
            </span>
          </div>
        </div>

        {/* Timeline Histogram Bars */}
        <div className="relative pt-6 pb-2">
          {/* Tooltip */}
          {hoveredBucket !== null && stats.timeBuckets[hoveredBucket] && (
            <div 
              className="absolute top-0 z-20 px-3 py-1.5 bg-slate-950 border border-slate-700 rounded-lg text-xs font-mono shadow-xl pointer-events-none transition-all"
              style={{
                left: `${Math.min(85, Math.max(10, (hoveredBucket / (stats.timeBuckets.length - 1)) * 100))}%`,
                transform: 'translateX(-50%)',
              }}
            >
              <div className="text-cyan-400 font-bold">
                Time: {stats.timeBuckets[hoveredBucket].timeLabel}
              </div>
              <div className="text-white">
                Total: {stats.timeBuckets[hoveredBucket].totalPackets} pkts ({formatBytes(stats.timeBuckets[hoveredBucket].bytes)})
              </div>
              <div className="text-[10px] text-slate-400 mt-0.5 space-x-2">
                <span>HTTP: {stats.timeBuckets[hoveredBucket].http}</span>
                <span>DNS: {stats.timeBuckets[hoveredBucket].dns}</span>
                <span>TLS: {stats.timeBuckets[hoveredBucket].tls}</span>
                <span>TCP: {stats.timeBuckets[hoveredBucket].tcp}</span>
              </div>
            </div>
          )}

          {/* Bar Chart Container */}
          <div className="h-36 flex items-end gap-1 sm:gap-2 px-1 border-b border-slate-800">
            {stats.timeBuckets.map((bucket, idx) => {
              const heightPercent = Math.max(8, Math.round((bucket.totalPackets / maxBucketPackets) * 100));
              const isHovered = hoveredBucket === idx;

              return (
                <div
                  key={idx}
                  onMouseEnter={() => setHoveredBucket(idx)}
                  onMouseLeave={() => setHoveredBucket(null)}
                  className="flex-1 h-full flex flex-col justify-end group cursor-pointer relative"
                >
                  <div
                    className={`w-full rounded-t transition-all flex flex-col justify-end overflow-hidden ${
                      isHovered ? 'ring-2 ring-cyan-400 ring-offset-1 ring-offset-slate-900' : ''
                    }`}
                    style={{ height: `${heightPercent}%` }}
                  >
                    {/* Stacked sub-bars */}
                    {bucket.http > 0 && (
                      <div
                        style={{ height: `${(bucket.http / (bucket.totalPackets || 1)) * 100}%` }}
                        className="bg-emerald-500 w-full"
                      />
                    )}
                    {bucket.dns > 0 && (
                      <div
                        style={{ height: `${(bucket.dns / (bucket.totalPackets || 1)) * 100}%` }}
                        className="bg-cyan-500 w-full"
                      />
                    )}
                    {bucket.tls > 0 && (
                      <div
                        style={{ height: `${(bucket.tls / (bucket.totalPackets || 1)) * 100}%` }}
                        className="bg-purple-500 w-full"
                      />
                    )}
                    {bucket.tcp > 0 && (
                      <div
                        style={{ height: `${(bucket.tcp / (bucket.totalPackets || 1)) * 100}%` }}
                        className="bg-indigo-500 w-full"
                      />
                    )}
                    {bucket.other > 0 && (
                      <div
                        style={{ height: `${(bucket.other / (bucket.totalPackets || 1)) * 100}%` }}
                        className="bg-slate-500 w-full"
                      />
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Time axis labels */}
          <div className="flex justify-between text-[10px] font-mono text-slate-500 mt-2 px-1">
            <span>0.0s (Capture Start)</span>
            <span>{stats.durationSeconds}s (Capture End)</span>
          </div>
        </div>
      </div>

      {/* 2. Middle Row: Protocol Distribution & Destination Ports */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Protocol Breakdown */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-4">
            <PieChart className="w-4 h-4 text-purple-400" />
            <span>Protocol Hierarchy &amp; Distribution</span>
          </h3>

          <div className="space-y-3">
            {(Object.entries(stats.protocolCounts) as [string, number][])
              .sort((a, b) => b[1] - a[1])
              .map(([proto, count]) => {
                const percent = Number(((count / totalPackets) * 100).toFixed(1));
                const bytes = stats.protocolBytes[proto] || 0;
                const color = getProtocolColor(proto);

                return (
                  <div key={proto} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-semibold text-white flex items-center gap-1.5">
                        <span className={`w-2.5 h-2.5 rounded-sm ${color.bg}`} />
                        <span>{proto}</span>
                      </span>
                      <span className="text-slate-400 font-mono">
                        {count.toLocaleString()} pkts ({percent}%) • {formatBytes(bytes)}
                      </span>
                    </div>

                    <div className="w-full bg-slate-950 h-2 rounded-full overflow-hidden border border-slate-800/80">
                      <div
                        className={`h-full ${color.bg} rounded-full transition-all duration-500`}
                        style={{ width: `${percent}%` }}
                      />
                    </div>
                  </div>
                );
              })}
          </div>
        </div>

        {/* Destination Port Distribution */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-emerald-400" />
            <span>Service &amp; Destination Port Distribution</span>
          </h3>

          <div className="space-y-2.5">
            {stats.portDistribution.slice(0, 6).map((item) => {
              const maxPortPackets = Math.max(1, ...stats.portDistribution.map(p => p.packets));
              const percent = Math.round((item.packets / maxPortPackets) * 100);

              return (
                <div key={item.port} className="bg-slate-950 p-2.5 rounded-lg border border-slate-800/70">
                  <div className="flex justify-between items-center text-xs mb-1.5">
                    <div className="flex items-center gap-2 font-mono">
                      <span className="px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 font-bold">
                        Port {item.port}
                      </span>
                      <span className="text-slate-300 font-sans font-medium">
                        {item.service}
                      </span>
                    </div>

                    <span className="text-slate-400 font-mono text-[11px]">
                      {item.packets} packets ({formatBytes(item.bytes)})
                    </span>
                  </div>

                  <div className="w-full bg-slate-900 h-1.5 rounded-full overflow-hidden">
                    <div
                      className="bg-emerald-500 h-full rounded-full transition-all duration-300"
                      style={{ width: `${percent}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

      </div>

      {/* 3. Bottom Row: Top Talkers & Conversations Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Top Talkers Table */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
            <Radio className="w-4 h-4 text-indigo-400" />
            <span>Top Talkers (Active Host IP Addresses)</span>
          </h3>

          <div className="overflow-x-auto">
            <table className="w-full text-xs text-left">
              <thead>
                <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-wider text-[10px] font-mono">
                  <th className="py-2 font-medium">IP Address</th>
                  <th className="py-2 font-medium text-right">Sent</th>
                  <th className="py-2 font-medium text-right">Rcvd</th>
                  <th className="py-2 font-medium text-right">Bandwidth</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/50 font-mono">
                {stats.topTalkers.slice(0, 7).map((host) => (
                  <tr key={host.ip} className="hover:bg-slate-800/30">
                    <td className="py-2 text-cyan-300 font-semibold">{host.ip}</td>
                    <td className="py-2 text-right text-slate-400">{host.sentPackets}</td>
                    <td className="py-2 text-right text-slate-400">{host.receivedPackets}</td>
                    <td className="py-2 text-right text-white font-semibold">
                      {formatBytes(host.totalBytes)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Active Conversations Matrix */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm">
          <h3 className="text-sm font-bold text-white flex items-center gap-2 mb-3">
            <ArrowLeftRight className="w-4 h-4 text-amber-400" />
            <span>Network Conversation Matrix</span>
          </h3>

          <div className="space-y-2 overflow-y-auto max-h-72 pr-1">
            {stats.conversations.slice(0, 8).map((conv) => (
              <div 
                key={conv.id}
                onClick={() => onFilterConversation?.(conv.ipA, conv.ipB)}
                className="bg-slate-950 hover:bg-slate-800/60 p-2.5 rounded-lg border border-slate-800/70 transition-colors flex items-center justify-between text-xs font-mono cursor-pointer group"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-amber-300">
                    {conv.protocol}
                  </span>
                  <span className="text-slate-300 truncate">
                    {conv.ipA} <span className="text-slate-600">↔</span> {conv.ipB}
                  </span>
                </div>

                <div className="text-right text-slate-400 shrink-0 text-[11px]">
                  <span className="text-white font-semibold">{conv.packets}</span> pkts • {formatBytes(conv.bytes)}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>

    </div>
  );
};
