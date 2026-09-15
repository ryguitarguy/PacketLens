import React from 'react';
import { 
  ShieldAlert, 
  Upload, 
  Download, 
  FileText, 
  Layers, 
  FolderOpen,
  X
} from 'lucide-react';
import { SAMPLE_PCAPS } from '../services/samplePcaps';

interface NavbarProps {
  currentFilename: string;
  packetCount: number;
  unencryptedCount: number;
  anomalyCount: number;
  hasCapture: boolean;
  activeTab: 'unencrypted' | 'anomalies' | 'traffic' | 'packets';
  setActiveTab: (tab: 'unencrypted' | 'anomalies' | 'traffic' | 'packets') => void;
  onFileUpload: (file: File) => void;
  onSelectSample: (sampleId: string) => void;
  onExportReport: () => void;
  onDownloadCurrentPcap: () => void;
  onClearCapture: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  currentFilename,
  packetCount,
  unencryptedCount,
  anomalyCount,
  hasCapture,
  activeTab,
  setActiveTab,
  onFileUpload,
  onSelectSample,
  onExportReport,
  onDownloadCurrentPcap,
  onClearCapture,
}) => {
  const fileInputRef = React.useRef<HTMLInputElement>(null);
  const [showSampleDropdown, setShowSampleDropdown] = React.useState(false);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      onFileUpload(e.target.files[0]);
    }
  };

  return (
    <header className="bg-slate-900/90 border-b border-slate-800 backdrop-blur-md sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          
          {/* Logo & Title */}
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 shrink-0">
              <ShieldAlert className="w-5 h-5 text-white" />
            </div>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-bold text-white text-base tracking-tight truncate font-sans">
                  PacketLens
                </span>
                <span className="text-[10px] uppercase font-mono tracking-wider px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                  PCAP Forensics
                </span>
              </div>
              <div className="flex items-center gap-2 text-xs text-slate-400 font-mono truncate">
                {hasCapture ? (
                  <>
                    <span className="truncate text-slate-300 font-semibold">{currentFilename}</span>
                    <span>• {packetCount.toLocaleString()} pkts</span>
                    <button
                      id="btn-clear-capture"
                      onClick={onClearCapture}
                      title="Close capture and return to scenarios"
                      className="text-[11px] font-sans px-1.5 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-rose-300 border border-slate-700 transition-colors flex items-center gap-1 cursor-pointer ml-1"
                    >
                      <X className="w-3 h-3" />
                      <span>Close</span>
                    </button>
                  </>
                ) : (
                  <span className="text-slate-400">Select a forensic sample or upload a PCAP</span>
                )}
              </div>
            </div>
          </div>

          {/* Center Navigation Tabs (Only when capture is loaded) */}
          {hasCapture && (
            <nav className="hidden md:flex items-center bg-slate-950/70 p-1 rounded-xl border border-slate-800">
              <button
                id="tab-unencrypted"
                onClick={() => setActiveTab('unencrypted')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                  activeTab === 'unencrypted'
                    ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <span>Cleartext Data</span>
                {unencryptedCount > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500 text-slate-950">
                    {unencryptedCount}
                  </span>
                )}
              </button>

              <button
                id="tab-anomalies"
                onClick={() => setActiveTab('anomalies')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                  activeTab === 'anomalies'
                    ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <span>Security Anomalies</span>
                {anomalyCount > 0 && (
                  <span className="px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-rose-500 text-white">
                    {anomalyCount}
                  </span>
                )}
              </button>

              <button
                id="tab-traffic"
                onClick={() => setActiveTab('traffic')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                  activeTab === 'traffic'
                    ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Layers className="w-3.5 h-3.5" />
                <span>Traffic Patterns</span>
              </button>

              <button
                id="tab-packets"
                onClick={() => setActiveTab('packets')}
                className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all flex items-center gap-2 ${
                  activeTab === 'packets'
                    ? 'bg-indigo-500/20 text-indigo-300 border border-indigo-500/30 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <FileText className="w-3.5 h-3.5" />
                <span>Raw Packets &amp; Hex</span>
              </button>
            </nav>
          )}

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            
            {/* Samples Dropdown */}
            <div className="relative">
              <button
                id="btn-sample-pcaps"
                onClick={() => setShowSampleDropdown(!showSampleDropdown)}
                className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors flex items-center gap-1.5"
              >
                <FolderOpen className="w-3.5 h-3.5 text-cyan-400" />
                <span>Samples</span>
              </button>

              {showSampleDropdown && (
                <>
                  <div 
                    className="fixed inset-0 z-40" 
                    onClick={() => setShowSampleDropdown(false)}
                  />
                  <div 
                    className="absolute right-0 mt-2 w-80 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl py-2 z-50 animate-in fade-in zoom-in-95 duration-100"
                  >
                    <div className="px-3 py-1.5 text-[11px] font-semibold text-slate-400 uppercase tracking-wider border-b border-slate-800">
                      Load Forensic Sample PCAP
                    </div>
                    <div className="max-h-96 overflow-y-auto divide-y divide-slate-800/60">
                      {SAMPLE_PCAPS.map((sample) => (
                        <button
                          key={sample.id}
                          id={`btn-sample-${sample.id}`}
                          onClick={() => {
                            onSelectSample(sample.id);
                            setShowSampleDropdown(false);
                          }}
                          className="w-full text-left px-3.5 py-2.5 text-xs text-slate-300 hover:bg-slate-800/90 hover:text-white transition-colors flex flex-col gap-1 cursor-pointer"
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-semibold text-cyan-300">{sample.name}</span>
                            <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 font-mono shrink-0">
                              {sample.badge}
                            </span>
                          </div>
                          <span className="text-[11px] text-slate-400 line-clamp-2 leading-relaxed">{sample.description}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Upload Button */}
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".pcap,.pcapng,.cap"
              className="hidden"
            />
            <button
              id="btn-upload-pcap"
              onClick={() => fileInputRef.current?.click()}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold shadow-md shadow-cyan-600/20 transition-colors flex items-center gap-1.5"
            >
              <Upload className="w-3.5 h-3.5" />
              <span>Upload PCAP</span>
            </button>

            {/* Download Raw PCAP (Only when capture is loaded) */}
            {hasCapture && (
              <>
                <button
                  id="btn-download-pcap"
                  onClick={onDownloadCurrentPcap}
                  title="Download binary PCAP file"
                  className="p-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs border border-slate-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                </button>

                {/* Export Report */}
                <button
                  id="btn-export-report"
                  onClick={onExportReport}
                  title="Export forensic audit report"
                  className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium border border-slate-700 transition-colors hidden sm:flex items-center gap-1.5"
                >
                  <FileText className="w-3.5 h-3.5 text-amber-400" />
                  <span>Audit Report</span>
                </button>
              </>
            )}

          </div>
        </div>

        {/* Mobile Nav Tabs (Only when capture is loaded) */}
        {hasCapture && (
          <div className="flex md:hidden items-center justify-around py-2 border-t border-slate-800 text-xs">
            <button
              onClick={() => setActiveTab('unencrypted')}
              className={`px-2 py-1 rounded ${activeTab === 'unencrypted' ? 'text-amber-400 font-bold' : 'text-slate-400'}`}
            >
              Cleartext ({unencryptedCount})
            </button>
            <button
              onClick={() => setActiveTab('anomalies')}
              className={`px-2 py-1 rounded ${activeTab === 'anomalies' ? 'text-rose-400 font-bold' : 'text-slate-400'}`}
            >
              Anomalies ({anomalyCount})
            </button>
            <button
              onClick={() => setActiveTab('traffic')}
              className={`px-2 py-1 rounded ${activeTab === 'traffic' ? 'text-cyan-400 font-bold' : 'text-slate-400'}`}
            >
              Traffic
            </button>
            <button
              onClick={() => setActiveTab('packets')}
              className={`px-2 py-1 rounded ${activeTab === 'packets' ? 'text-indigo-400 font-bold' : 'text-slate-400'}`}
            >
              Packets
            </button>
          </div>
        )}

      </div>
    </header>
  );
};
