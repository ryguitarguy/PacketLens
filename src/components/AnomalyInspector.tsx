import React from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  ExternalLink, 
  CheckCircle2, 
  Info, 
  ArrowRight,
  FileCheck
} from 'lucide-react';
import { SecurityAnomaly } from '../types';

interface AnomalyInspectorProps {
  anomalies: SecurityAnomaly[];
  onSelectPacket: (packetId: number) => void;
}

export const AnomalyInspector: React.FC<AnomalyInspectorProps> = ({
  anomalies,
  onSelectPacket,
}) => {
  const getSeverityStyle = (severity: string) => {
    switch (severity) {
      case 'critical':
        return {
          badge: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
          dot: 'bg-rose-500',
          border: 'border-rose-900/50 hover:border-rose-700/80',
          icon: <ShieldAlert className="w-5 h-5 text-rose-400" />
        };
      case 'high':
        return {
          badge: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
          dot: 'bg-amber-500',
          border: 'border-amber-900/40 hover:border-amber-700/80',
          icon: <AlertTriangle className="w-5 h-5 text-amber-400" />
        };
      case 'medium':
        return {
          badge: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
          dot: 'bg-yellow-500',
          border: 'border-yellow-900/40 hover:border-yellow-700/80',
          icon: <Info className="w-5 h-5 text-yellow-400" />
        };
      default:
        return {
          badge: 'bg-slate-800 text-slate-400 border-slate-700',
          dot: 'bg-slate-400',
          border: 'border-slate-800 hover:border-slate-700',
          icon: <Info className="w-5 h-5 text-slate-400" />
        };
    }
  };

  return (
    <div className="space-y-4">
      
      {/* Header Info */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-400" />
            <span>Automated Security Anomaly Detection Engine</span>
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Rule-based heuristics and behavioral analysis cross-referenced against MITRE ATT&amp;CK enterprise tactics.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-lg bg-slate-950 border border-slate-800 text-slate-300 font-mono">
            {anomalies.length} Flagged Anomalies
          </span>
        </div>
      </div>

      {/* Anomaly Cards List */}
      {anomalies.length === 0 ? (
        <div className="bg-slate-900/40 border border-dashed border-slate-800 rounded-xl p-12 text-center">
          <CheckCircle2 className="w-10 h-10 text-emerald-500 mx-auto mb-3" />
          <h4 className="text-sm font-semibold text-slate-200">No Security Anomalies Flagged</h4>
          <p className="text-xs text-slate-500 mt-1 max-w-sm mx-auto">
            All packets analyzed comply with expected traffic baselines and no unencrypted credentials or malicious patterns were observed.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {anomalies.map(anomaly => {
            const style = getSeverityStyle(anomaly.severity);

            return (
              <div
                key={anomaly.id}
                className={`bg-slate-900/80 border ${style.border} rounded-xl p-5 transition-all shadow-sm flex flex-col gap-4`}
              >
                {/* Header: Title, Severity, MITRE ATT&CK */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
                  <div className="flex items-start gap-3">
                    <div className="p-2 rounded-xl bg-slate-950 border border-slate-800 shrink-0 mt-0.5">
                      {style.icon}
                    </div>
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <h4 className="text-sm font-bold text-white tracking-tight">
                          {anomaly.title}
                        </h4>
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border ${style.badge}`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${style.dot} animate-pulse`} />
                          {anomaly.severity}
                        </span>
                        <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300 border border-slate-700">
                          {anomaly.category}
                        </span>
                      </div>
                      
                      <div className="flex items-center gap-2 mt-1 text-xs font-mono text-slate-400">
                        <span>{anomaly.sourceIp}{anomaly.sourcePort ? `:${anomaly.sourcePort}` : ''}</span>
                        <ArrowRight className="w-3 h-3 text-slate-600 inline" />
                        <span>{anomaly.destinationIp}{anomaly.destinationPort ? `:${anomaly.destinationPort}` : ''}</span>
                        <span className="text-slate-600">•</span>
                        <span className="text-cyan-400 font-semibold">{anomaly.protocol}</span>
                      </div>
                    </div>
                  </div>

                  {/* MITRE ATT&CK Tag */}
                  <div className="flex items-center gap-2 self-start sm:self-center shrink-0">
                    <div className="text-right">
                      <div className="text-[10px] text-slate-500 uppercase tracking-wider font-mono">MITRE ATT&amp;CK</div>
                      <div className="text-xs font-mono font-semibold text-rose-300">
                        {anomaly.mitreId}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Description */}
                <p className="text-xs text-slate-300 leading-relaxed">
                  {anomaly.description}
                </p>

                {/* Evidence Details */}
                <div className="bg-slate-950/80 rounded-lg p-3 border border-slate-800/80 text-xs font-mono">
                  <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2 font-sans font-bold flex items-center gap-1">
                    <FileCheck className="w-3 h-3" />
                    <span>Forensic Evidence Metrics</span>
                  </div>

                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 text-slate-300">
                    {Object.entries(anomaly.evidence).map(([key, val]) => (
                      <div key={key} className="bg-slate-900/60 p-2 rounded border border-slate-800/50">
                        <span className="text-[10px] text-slate-500 block capitalize">
                          {key.replace(/([A-Z])/g, ' $1')}
                        </span>
                        <span className="text-xs font-semibold text-cyan-300 break-words">
                          {Array.isArray(val) ? val.join(', ') : String(val)}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Associated Packets */}
                {anomaly.packetIds && anomaly.packetIds.length > 0 && (
                  <div className="flex items-center gap-2 flex-wrap pt-1">
                    <span className="text-[11px] text-slate-500 font-mono">Associated Packets:</span>
                    {anomaly.packetIds.slice(0, 8).map(pktId => (
                      <button
                        key={pktId}
                        onClick={() => onSelectPacket(pktId)}
                        className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 transition-colors flex items-center gap-1"
                      >
                        <span>#{pktId}</span>
                        <ExternalLink className="w-2.5 h-2.5 text-cyan-400" />
                      </button>
                    ))}
                    {anomaly.packetIds.length > 8 && (
                      <span className="text-[11px] text-slate-500 font-mono">
                        +{anomaly.packetIds.length - 8} more
                      </span>
                    )}
                  </div>
                )}

              </div>
            );
          })}
        </div>
      )}

    </div>
  );
};
