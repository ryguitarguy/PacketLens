import React, { useState, useEffect, useCallback } from 'react';
import { Navbar } from './components/Navbar';
import { SummaryCards } from './components/SummaryCards';
import { UnencryptedDataView } from './components/UnencryptedDataView';
import { AnomalyInspector } from './components/AnomalyInspector';
import { TrafficVisualizer } from './components/TrafficVisualizer';
import { PacketTableView } from './components/PacketTableView';
import { ExportReportModal } from './components/ExportReportModal';
import { PcapParser } from './services/pcapParser';
import { UnencryptedScanner } from './services/unencryptedScanner';
import { AnomalyDetector } from './services/anomalyDetector';
import { StatsEngine } from './services/statsEngine';
import { SAMPLE_PCAPS } from './services/samplePcaps';
import { AnalysisResult } from './types';
import { 
  Upload, 
  ShieldAlert, 
  FileWarning, 
  Loader2, 
  HardDrive,
  FolderOpen
} from 'lucide-react';

export function App() {
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [currentBuffer, setCurrentBuffer] = useState<ArrayBuffer | null>(null);
  const [activeTab, setActiveTab] = useState<'unencrypted' | 'anomalies' | 'traffic' | 'packets'>('unencrypted');
  const [selectedPacketId, setSelectedPacketId] = useState<number | undefined>(undefined);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [isDraggingOver, setIsDraggingOver] = useState<boolean>(false);

  // Process raw PCAP ArrayBuffer through parsing and analytics engines
  const processPcapBuffer = useCallback((buffer: ArrayBuffer, filename: string) => {
    setIsLoading(true);
    setErrorMessage(null);

    try {
      // 1. Binary PCAP / PCAPNG parsing
      const parseOutput = PcapParser.parse(buffer);
      if (parseOutput.packets.length === 0) {
        throw new Error('No valid IP frames found in capture file.');
      }

      // 2. Cleartext & credential harvesting
      const cleartextItems = UnencryptedScanner.scan(parseOutput.packets);

      // 3. Security anomaly detection
      const anomalies = AnomalyDetector.detect(parseOutput.packets, cleartextItems);

      // 4. Traffic statistics engine
      const stats = StatsEngine.compute(parseOutput.packets);

      setAnalysisResult({
        filename,
        fileSize: buffer.byteLength,
        parsedPackets: parseOutput.packets,
        cleartextItems,
        anomalies,
        stats,
      });
      setCurrentBuffer(buffer);
      setSelectedPacketId(parseOutput.packets[0]?.id);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to parse PCAP file';
      setErrorMessage(msg);
    } finally {
      setIsLoading(false);
    }
  }, []);

  // Initial load: populate with realistic default forensic sample
  useEffect(() => {
    const defaultSample = SAMPLE_PCAPS[0];
    const buf = defaultSample.generate();
    processPcapBuffer(buf, 'audit_credentials_leak.pcap');
  }, [processPcapBuffer]);

  // Load a chosen sample
  const handleSelectSample = (sampleId: string) => {
    const sample = SAMPLE_PCAPS.find(s => s.id === sampleId) || SAMPLE_PCAPS[0];
    const buf = sample.generate();
    processPcapBuffer(buf, `${sample.id}.pcap`);
  };

  // Upload user file
  const handleFileUpload = (file: File) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result instanceof ArrayBuffer) {
        processPcapBuffer(e.target.result, file.name);
      }
    };
    reader.onerror = () => {
      setErrorMessage('Failed to read uploaded file');
    };
    reader.readAsArrayBuffer(file);
  };

  // Download currently loaded PCAP as binary file
  const handleDownloadPcap = () => {
    if (!currentBuffer || !analysisResult) return;
    const blob = new Blob([currentBuffer], { type: 'application/vnd.tcpdump.pcap' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = analysisResult.filename.endsWith('.pcap') 
      ? analysisResult.filename 
      : `${analysisResult.filename}.pcap`;
    a.click();
    URL.revokeObjectURL(url);
  };

  // Drag and drop handlers
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDraggingOver(true);
  };

  const handleDragLeave = () => {
    setIsDraggingOver(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDraggingOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files[0]);
    }
  };

  // Jump to packet in inspector
  const handleSelectPacketAndNavigate = (packetId: number) => {
    setSelectedPacketId(packetId);
    setActiveTab('packets');
  };

  return (
    <div 
      className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200"
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
    >
      {/* Drag & Drop Visual Overlay */}
      {isDraggingOver && (
        <div className="fixed inset-0 bg-slate-950/90 border-4 border-dashed border-cyan-400 z-50 flex items-center justify-center p-6 backdrop-blur-md">
          <div className="text-center space-y-3">
            <div className="w-16 h-16 rounded-2xl bg-cyan-500/20 border border-cyan-500/40 flex items-center justify-center mx-auto text-cyan-400 animate-bounce">
              <Upload className="w-8 h-8" />
            </div>
            <h3 className="text-xl font-bold text-white">Drop PCAP file to inspect</h3>
            <p className="text-sm text-slate-400 font-mono">
              Supports standard Libpcap (.pcap), PCAP Next Generation (.pcapng), and TCPDump (.cap)
            </p>
          </div>
        </div>
      )}

      {/* Main App Navigation */}
      <Navbar
        currentFilename={analysisResult?.filename || 'No capture loaded'}
        packetCount={analysisResult?.parsedPackets.length || 0}
        unencryptedCount={analysisResult?.cleartextItems.length || 0}
        anomalyCount={analysisResult?.anomalies.length || 0}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onFileUpload={handleFileUpload}
        onSelectSample={handleSelectSample}
        onExportReport={() => setIsExportModalOpen(true)}
        onDownloadCurrentPcap={handleDownloadPcap}
      />

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* Error Notification */}
        {errorMessage && (
          <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 flex items-start gap-3 text-rose-300 text-xs">
            <FileWarning className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div>
              <p className="font-bold text-sm">Failed to parse packet capture</p>
              <p className="mt-0.5">{errorMessage}</p>
              <p className="mt-2 text-slate-400">
                Ensure the file is a valid standard PCAP or PCAPNG file. You can load one of the built-in forensic sample captures using the &quot;Samples&quot; menu above.
              </p>
            </div>
          </div>
        )}

        {/* Loading Spinner */}
        {isLoading && (
          <div className="py-24 text-center space-y-4">
            <Loader2 className="w-10 h-10 text-cyan-400 animate-spin mx-auto" />
            <div className="space-y-1">
              <h3 className="text-base font-semibold text-white">Analyzing Packet Stream</h3>
              <p className="text-xs text-slate-400 font-mono">
                Decoding Ethernet/IP/TCP frames, extracting unencrypted credentials, and running anomaly heuristics...
              </p>
            </div>
          </div>
        )}

        {/* Main Content When Data Loaded */}
        {!isLoading && analysisResult && (
          <div className="space-y-6">
            
            {/* Top Metric Cards */}
            <SummaryCards
              stats={analysisResult.stats}
              cleartextItems={analysisResult.cleartextItems}
              anomalies={analysisResult.anomalies}
              onTabChange={setActiveTab}
            />

            {/* Quick Sample Switcher Chips (Helper banner) */}
            <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-3 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs">
              <div className="flex items-center gap-2 text-slate-300">
                <FolderOpen className="w-4 h-4 text-cyan-400" />
                <span>Forensic Pre-loaded Scenarios:</span>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                {SAMPLE_PCAPS.map((sample) => {
                  const isActive = analysisResult.filename.includes(sample.id) || 
                    (sample.id === 'credential_leak_audit' && analysisResult.filename === 'audit_credentials_leak.pcap');
                  return (
                    <button
                      key={sample.id}
                      onClick={() => handleSelectSample(sample.id)}
                      className={`px-2.5 py-1 rounded-lg text-[11px] font-medium transition-all ${
                        isActive
                          ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm font-semibold'
                          : 'bg-slate-800/80 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-700/60'
                      }`}
                    >
                      {sample.name}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Tab Views */}
            {activeTab === 'unencrypted' && (
              <UnencryptedDataView
                items={analysisResult.cleartextItems}
                onSelectPacket={handleSelectPacketAndNavigate}
              />
            )}

            {activeTab === 'anomalies' && (
              <AnomalyInspector
                anomalies={analysisResult.anomalies}
                onSelectPacket={handleSelectPacketAndNavigate}
              />
            )}

            {activeTab === 'traffic' && (
              <TrafficVisualizer
                stats={analysisResult.stats}
                onFilterConversation={() => {
                  setActiveTab('packets');
                }}
              />
            )}

            {activeTab === 'packets' && (
              <PacketTableView
                packets={analysisResult.parsedPackets}
                selectedPacketId={selectedPacketId}
                onSelectPacket={setSelectedPacketId}
              />
            )}

          </div>
        )}

      </main>

      {/* Export Report Modal */}
      {isExportModalOpen && analysisResult && (
        <ExportReportModal
          data={analysisResult}
          onClose={() => setIsExportModalOpen(false)}
        />
      )}

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-4 mt-auto">
        <div className="max-w-7xl mx-auto px-4 text-center text-xs text-slate-500 font-mono flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>PacketLens PCAP Forensics Engine • Deep Packet Inspection &amp; Anomaly Detection</span>
          <span>Zero Server Storage: In-memory stream analysis</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
