import React, { useState, useCallback, useRef } from 'react';
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
import { AnalysisResult, AnalysisProgress } from './types';
import { 
  Upload, 
  ShieldAlert, 
  FileWarning, 
  Loader2, 
  HardDrive,
  FolderOpen,
  Play,
  ArrowRight,
  AlertTriangle,
  X,
  Cpu,
  Zap,
  Sliders,
  Gauge
} from 'lucide-react';

const formatFileSize = (bytes: number): string => {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
};

const CAPACITY_OPTIONS = [
  { value: 100000, label: '100,000 frames', desc: 'Fast / Standard' },
  { value: 250000, label: '250,000 frames', desc: 'Deep Forensics (Default)' },
  { value: 500000, label: '500,000 frames', desc: 'Ultra-High Capacity' },
  { value: 1000000, label: '1,000,000 frames', desc: 'Maximum Stream Capacity' },
];

export function App() {
  const [analysisResult, setAnalysisResult] = useState<AnalysisResult | null>(null);
  const [currentBuffer, setCurrentBuffer] = useState<ArrayBuffer | null>(null);
  const [activeTab, setActiveTab] = useState<'unencrypted' | 'anomalies' | 'traffic' | 'packets'>('unencrypted');
  const [selectedPacketId, setSelectedPacketId] = useState<number | undefined>(undefined);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [loadingProgress, setLoadingProgress] = useState<AnalysisProgress | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isExportModalOpen, setIsExportModalOpen] = useState<boolean>(false);
  const [isDraggingOver, setIsDraggingOver] = useState<boolean>(false);
  const [packetCapacity, setPacketCapacity] = useState<number>(250000);
  const landingFileInputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<{ aborted: boolean }>({ aborted: false });

  // Process raw PCAP ArrayBuffer through parsing and analytics engines asynchronously
  const processPcapBuffer = useCallback(async (buffer: ArrayBuffer, filename: string, capacityOverride?: number) => {
    setIsLoading(true);
    setErrorMessage(null);
    abortRef.current = { aborted: false };
    const limit = capacityOverride ?? packetCapacity;

    try {
      setLoadingProgress({
        stage: 'parsing',
        percent: 5,
        message: `Initializing 0-copy frame parser (Capacity up to ${limit.toLocaleString()} frames)...`,
        packetsCount: 0,
      });

      // 1. Binary PCAP / PCAPNG parsing with chunked yielding & zero-copy string interning
      const parseOutput = await PcapParser.parseAsync(
        buffer,
        (p) => {
          setLoadingProgress({
            stage: 'parsing',
            percent: Math.min(60, Math.round(p.percent * 0.6)),
            message: `Parsing frames & headers (${p.parsedCount.toLocaleString()} indexed)...`,
            packetsCount: p.parsedCount,
          });
        },
        () => abortRef.current.aborted,
        limit
      );

      if (parseOutput.packets.length === 0) {
        throw new Error('No valid IP frames found in capture file.');
      }

      // 2. Cleartext & credential harvesting with non-blocking stream analyzer
      setLoadingProgress({
        stage: 'scanning',
        percent: 65,
        message: `Scanning ${parseOutput.packets.length.toLocaleString()} packets for plaintext credentials & tokens...`,
        packetsCount: parseOutput.packets.length,
      });

      const cleartextItems = await UnencryptedScanner.scanAsync(
        parseOutput.packets,
        (p) => {
          setLoadingProgress({
            stage: 'scanning',
            percent: 65 + Math.round(p.percent * 0.15),
            message: `Harvesting credentials & auth secrets (${p.percent}%)...`,
            packetsCount: parseOutput.packets.length,
          });
        },
        () => abortRef.current.aborted
      );

      // 3. Security anomaly detection (single-pass chunked engine)
      setLoadingProgress({
        stage: 'anomalies',
        percent: 85,
        message: 'Evaluating MITRE ATT&CK techniques & network anomalies...',
        packetsCount: parseOutput.packets.length,
      });

      const anomalies = await AnomalyDetector.detectAsync(
        parseOutput.packets,
        cleartextItems,
        (p) => {
          setLoadingProgress({
            stage: 'anomalies',
            percent: 85 + Math.round(p.percent * 0.08),
            message: `Evaluating MITRE ATT&CK techniques & anomalies (${p.percent}%)...`,
            packetsCount: parseOutput.packets.length,
          });
        },
        () => abortRef.current.aborted
      );

      // 4. Traffic statistics engine (single-pass chunked async aggregation)
      setLoadingProgress({
        stage: 'stats',
        percent: 94,
        message: 'Generating traffic rate timeline & conversation matrix...',
        packetsCount: parseOutput.packets.length,
      });

      const stats = await StatsEngine.computeAsync(
        parseOutput.packets,
        (p) => {
          setLoadingProgress({
            stage: 'stats',
            percent: 94 + Math.round(p.percent * 0.05),
            message: `Aggregating traffic matrix & time buckets (${p.percent}%)...`,
            packetsCount: parseOutput.packets.length,
          });
        },
        () => abortRef.current.aborted
      );

      setAnalysisResult({
        filename,
        fileSize: buffer.byteLength,
        parsedPackets: parseOutput.packets,
        cleartextItems,
        anomalies,
        stats,
        truncated: parseOutput.truncated,
        totalPacketsInCapture: parseOutput.totalCount,
      });
      setCurrentBuffer(buffer);
      setSelectedPacketId(parseOutput.packets[0]?.id);
    } catch (err: unknown) {
      if (abortRef.current.aborted) {
        setErrorMessage(null);
      } else {
        const msg = err instanceof Error ? err.message : 'Failed to parse PCAP file';
        setErrorMessage(msg);
      }
    } finally {
      setIsLoading(false);
      setLoadingProgress(null);
    }
  }, [packetCapacity]);

  // Clear current capture and return to scenario picker
  const handleClearCapture = () => {
    abortRef.current = { aborted: true };
    setAnalysisResult(null);
    setCurrentBuffer(null);
    setSelectedPacketId(undefined);
    setErrorMessage(null);
    setLoadingProgress(null);
    setIsLoading(false);
  };

  // Load a chosen sample
  const handleSelectSample = (sampleId: string) => {
    const sample = SAMPLE_PCAPS.find(s => s.id === sampleId) || SAMPLE_PCAPS[0];
    const buf = sample.generate();
    processPcapBuffer(buf, `${sample.id}.pcap`);
  };

  // Upload user file
  const handleFileUpload = (file: File) => {
    setIsLoading(true);
    setErrorMessage(null);
    abortRef.current = { aborted: false };
    setLoadingProgress({
      stage: 'reading',
      percent: 2,
      message: `Reading ${file.name} (${formatFileSize(file.size)})...`,
    });

    const reader = new FileReader();
    reader.onload = (e) => {
      if (e.target?.result instanceof ArrayBuffer) {
        processPcapBuffer(e.target.result, file.name);
      }
    };
    reader.onerror = () => {
      setIsLoading(false);
      setLoadingProgress(null);
      setErrorMessage('Failed to read uploaded file');
    };
    reader.readAsArrayBuffer(file);
  };

  // Re-run analysis with a new capacity limit
  const handleChangeCapacityAndReanalyze = (newCapacity: number) => {
    setPacketCapacity(newCapacity);
    if (currentBuffer && analysisResult) {
      processPcapBuffer(currentBuffer, analysisResult.filename, newCapacity);
    }
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
      {/* Top Navigation */}
      <Navbar
        currentFilename={analysisResult?.filename || ''}
        packetCount={analysisResult?.parsedPackets.length || 0}
        unencryptedCount={analysisResult?.cleartextItems.length || 0}
        anomalyCount={analysisResult?.anomalies.length || 0}
        hasCapture={!!analysisResult}
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        onFileUpload={handleFileUpload}
        onSelectSample={handleSelectSample}
        onExportReport={() => setIsExportModalOpen(true)}
        onDownloadCurrentPcap={handleDownloadPcap}
        onClearCapture={handleClearCapture}
      />

      {/* Drag & Drop Visual Overlay */}
      {isDraggingOver && (
        <div className="fixed inset-0 z-50 bg-cyan-950/80 border-4 border-dashed border-cyan-400 backdrop-blur-sm flex flex-col items-center justify-center pointer-events-none p-6 text-center">
          <Upload className="w-16 h-16 text-cyan-400 mb-4 animate-bounce" />
          <h2 className="text-2xl font-bold text-white mb-2">Drop PCAP File to Analyze</h2>
          <p className="text-cyan-200 text-sm font-mono">Supports .pcap and .pcapng captures of any scale without UI freezing</p>
        </div>
      )}

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        
        {/* Error Alert */}
        {errorMessage && (
          <div className="mb-6 bg-rose-950/80 border border-rose-800 text-rose-200 p-4 rounded-xl flex items-center justify-between gap-3 shadow-lg">
            <div className="flex items-center gap-3">
              <FileWarning className="w-5 h-5 text-rose-400 shrink-0" />
              <div>
                <p className="text-sm font-semibold">PCAP Processing Error</p>
                <p className="text-xs text-rose-300 font-mono mt-0.5">{errorMessage}</p>
              </div>
            </div>
            <button
              onClick={() => handleSelectSample('credential_leak_audit')}
              className="px-3 py-1.5 bg-rose-500/20 hover:bg-rose-500/30 text-rose-200 border border-rose-500/40 rounded-lg text-xs font-semibold shrink-0 transition-colors flex items-center gap-1.5 cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>Load Test Sample</span>
            </button>
          </div>
        )}

        {/* Loading Spinner & Progress Status */}
        {isLoading && (
          <div className="py-16 max-w-xl mx-auto space-y-6 animate-in fade-in duration-200">
            <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl shadow-slate-950 space-y-5 text-center">
              <div className="relative w-16 h-16 mx-auto flex items-center justify-center">
                <div className="absolute inset-0 rounded-full border-4 border-slate-800 border-t-cyan-400 animate-spin" />
                <Cpu className="w-7 h-7 text-cyan-400" />
              </div>

              <div className="space-y-1.5">
                <h3 className="text-lg font-bold text-white font-sans tracking-tight">
                  {loadingProgress?.stage === 'reading' && 'Reading PCAP File...'}
                  {loadingProgress?.stage === 'parsing' && 'Decoding PCAP Frames (Non-Blocking)...'}
                  {loadingProgress?.stage === 'scanning' && 'Scanning for Cleartext Secrets...'}
                  {loadingProgress?.stage === 'anomalies' && 'Analyzing Security Threats...'}
                  {loadingProgress?.stage === 'stats' && 'Compiling Traffic Timeline...'}
                  {(!loadingProgress || loadingProgress?.stage === 'ready') && 'Analyzing Packet Stream...'}
                </h3>
                <p className="text-xs text-slate-400 font-mono">
                  {loadingProgress?.message || 'Processing capture frames asynchronously without UI thread locks...'}
                </p>
              </div>

              {/* Progress Bar */}
              <div className="space-y-2">
                <div className="w-full bg-slate-950 rounded-full h-2.5 overflow-hidden border border-slate-800">
                  <div 
                    className="bg-gradient-to-r from-cyan-500 via-indigo-500 to-emerald-400 h-full transition-all duration-300 rounded-full"
                    style={{ width: `${Math.max(5, loadingProgress?.percent || 5)}%` }}
                  />
                </div>
                <div className="flex justify-between items-center text-[11px] font-mono text-slate-500">
                  <span className="flex items-center gap-1.5 text-slate-400">
                    <Zap className="w-3 h-3 text-cyan-400" />
                    <span>{loadingProgress?.packetsCount ? `${loadingProgress.packetsCount.toLocaleString()} frames indexed` : '0-copy memory pipeline'}</span>
                  </span>
                  <span className="font-semibold text-cyan-400">{loadingProgress?.percent || 0}%</span>
                </div>
              </div>

              {/* Cancel Button */}
              <div className="pt-2">
                <button
                  type="button"
                  onClick={handleClearCapture}
                  className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors inline-flex items-center gap-1.5 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                  <span>Cancel Analysis</span>
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Initial Screen: File Upload + Forensic Scenario Chooser */}
        {!isLoading && !analysisResult && (
          <div className="py-8 space-y-8 max-w-5xl mx-auto animate-in fade-in duration-200">
            
            {/* Hero / Upload Box */}
            <div className="text-center space-y-3">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-xs font-mono mb-2">
                <Zap className="w-3.5 h-3.5 text-cyan-400" />
                <span>Zero-Freeze Non-Blocking Engine • Handles 100,000+ to 500,000+ Packets</span>
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold text-white tracking-tight font-sans">
                PCAP Cleartext &amp; Forensic Analyzer
              </h2>
              <p className="text-sm text-slate-400 max-w-2xl mx-auto leading-relaxed">
                Scan network packet captures for unencrypted passwords, HTTP Basic Auth, API tokens, sensitive PII, and security anomalies at high scale.
              </p>
            </div>

            {/* Capacity Limit Selector Bar */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row items-center justify-between gap-3 shadow-md">
              <div className="flex items-center gap-2.5 text-xs text-slate-300">
                <Gauge className="w-4 h-4 text-cyan-400" />
                <span className="font-semibold text-white">Capture Capacity Target:</span>
                <span className="text-slate-400 hidden sm:inline">Set max frames to index without browser lag:</span>
              </div>
              <div className="flex items-center gap-1.5 flex-wrap">
                {CAPACITY_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setPacketCapacity(opt.value)}
                    className={`px-2.5 py-1 rounded-lg text-xs font-mono transition-all cursor-pointer ${
                      packetCapacity === opt.value
                        ? 'bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20'
                        : 'bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700'
                    }`}
                  >
                    {opt.label.split(' ')[0]}
                  </button>
                ))}
              </div>
            </div>

            {/* Drag & Drop Upload Zone */}
            <div 
              onClick={() => landingFileInputRef.current?.click()}
              className="group border-2 border-dashed border-slate-700 hover:border-cyan-500/80 bg-slate-900/60 hover:bg-slate-900/90 rounded-2xl p-8 text-center transition-all cursor-pointer shadow-xl shadow-slate-950/50 flex flex-col items-center justify-center gap-3"
            >
              <input
                type="file"
                ref={landingFileInputRef}
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    handleFileUpload(e.target.files[0]);
                  }
                }}
                accept=".pcap,.pcapng,.cap"
                className="hidden"
              />
              <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 group-hover:border-cyan-500/60 flex items-center justify-center text-cyan-400 group-hover:scale-105 transition-transform shadow-lg shadow-cyan-500/10">
                <Upload className="w-7 h-7" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-semibold text-white group-hover:text-cyan-300 transition-colors">
                  Drop your PCAP file here, or <span className="text-cyan-400 underline underline-offset-2">browse files</span>
                </p>
                <p className="text-xs text-slate-400 font-mono">
                  Supports Libpcap (.pcap), Wireshark NextGen (.pcapng), and TCPDump (.cap) up to 500,000+ packets
                </p>
              </div>
            </div>

            {/* Divider */}
            <div className="relative flex items-center justify-center">
              <div className="border-t border-slate-800 w-full" />
              <span className="bg-slate-950 px-4 text-xs uppercase font-mono tracking-widest text-slate-400 shrink-0">
                Or click a pre-loaded sample to test
              </span>
              <div className="border-t border-slate-800 w-full" />
            </div>

            {/* Scenario Cards Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {SAMPLE_PCAPS.map((sample) => (
                <div 
                  key={sample.id}
                  className="bg-slate-900 border border-slate-800 hover:border-cyan-500/50 hover:shadow-lg hover:shadow-cyan-950/20 rounded-xl p-5 space-y-4 transition-all flex flex-col justify-between"
                >
                  <div className="space-y-2.5">
                    <div className="flex items-center justify-between gap-2">
                      <h3 className="font-bold text-sm text-white flex items-center gap-2">
                        <span>{sample.name}</span>
                      </h3>
                      <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700 font-mono shrink-0">
                        {sample.badge}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">
                      {sample.description}
                    </p>
                    <div className="flex flex-wrap gap-1.5 pt-1">
                      {sample.highlights.map((h, i) => (
                        <span key={i} className="text-[10px] px-2 py-0.5 rounded bg-slate-950 text-slate-400 border border-slate-800 font-mono">
                          {h}
                        </span>
                      ))}
                    </div>
                  </div>

                  <button
                    id={`btn-landing-sample-${sample.id}`}
                    onClick={() => handleSelectSample(sample.id)}
                    className="w-full mt-2 px-3.5 py-2.5 bg-cyan-600/90 hover:bg-cyan-500 text-white rounded-lg text-xs font-semibold flex items-center justify-center gap-2 transition-colors cursor-pointer shadow-md shadow-cyan-900/30"
                  >
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Load &amp; Inspect Sample</span>
                  </button>
                </div>
              ))}
            </div>

          </div>
        )}

        {/* Main Content When Data Loaded */}
        {!isLoading && analysisResult && (
          <div className="space-y-6">
            
            {/* Capture Notification Banner */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5 text-xs font-mono text-slate-300 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-sm">
              <div className="flex items-center gap-2.5">
                <Zap className="w-4 h-4 text-cyan-400 shrink-0" />
                <span>
                  <strong className="text-white font-semibold">{analysisResult.parsedPackets.length.toLocaleString()} frames</strong> analyzed from{' '}
                  <span className="text-cyan-300 font-semibold">{analysisResult.filename}</span> ({formatFileSize(analysisResult.fileSize)}).
                  {analysisResult.truncated && (
                    <span className="text-amber-300 ml-1">
                      (Triaged first {analysisResult.parsedPackets.length.toLocaleString()} of {analysisResult.totalPacketsInCapture?.toLocaleString()} total capture frames).
                    </span>
                  )}
                </span>
              </div>

              {/* Quick Capacity Switcher */}
              <div className="flex items-center gap-2 self-end md:self-auto shrink-0">
                <span className="text-slate-500 text-[11px]">Capacity:</span>
                <div className="flex items-center gap-1 bg-slate-950 p-0.5 rounded-lg border border-slate-800">
                  {CAPACITY_OPTIONS.map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => handleChangeCapacityAndReanalyze(opt.value)}
                      title={`Re-analyze with capacity up to ${opt.value.toLocaleString()} frames`}
                      className={`px-2 py-0.5 rounded text-[11px] font-mono transition-colors cursor-pointer ${
                        packetCapacity === opt.value
                          ? 'bg-cyan-500 text-slate-950 font-bold'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {opt.label.split(' ')[0]}
                    </button>
                  ))}
                </div>
              </div>
            </div>

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
