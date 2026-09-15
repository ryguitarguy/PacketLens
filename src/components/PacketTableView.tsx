import React, { useState, useMemo, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  ChevronRight, 
  ChevronDown, 
  Layers, 
  Binary, 
  LockOpen, 
  AlertTriangle,
  FileCode,
  ArrowRight
} from 'lucide-react';
import { Packet } from '../types';

interface PacketTableViewProps {
  packets: Packet[];
  selectedPacketId?: number;
  onSelectPacket: (packetId: number) => void;
}

export const PacketTableView: React.FC<PacketTableViewProps> = ({
  packets,
  selectedPacketId,
  onSelectPacket,
}) => {
  const [filterQuery, setFilterQuery] = useState<string>('');
  const [protocolFilter, setProtocolFilter] = useState<string>('all');
  const [cleartextOnly, setCleartextOnly] = useState<boolean>(false);
  const [expandedSection, setExpandedSection] = useState<'l2' | 'l3' | 'l4' | 'l7' | 'hex' | null>('l7');

  const selectedPacket = useMemo(() => {
    return packets.find(p => p.id === selectedPacketId) || packets[0] || null;
  }, [packets, selectedPacketId]);

  // Sync selected packet when prop changes
  useEffect(() => {
    if (selectedPacketId) {
      setExpandedSection('l7');
    }
  }, [selectedPacketId]);

  // Filtered packets
  const filteredPackets = useMemo(() => {
    return packets.filter(p => {
      if (cleartextOnly && !p.isCleartext) return false;
      if (protocolFilter !== 'all' && p.protocol !== protocolFilter) return false;
      if (filterQuery.trim()) {
        const q = filterQuery.toLowerCase();
        const matchesIp = p.sourceIp.includes(q) || p.destIp.includes(q);
        const matchesPort = String(p.sourcePort || '').includes(q) || String(p.destPort || '').includes(q);
        const matchesProto = p.protocol.toLowerCase().includes(q);
        const matchesInfo = p.info.toLowerCase().includes(q);
        const matchesPayload = p.payloadText?.toLowerCase().includes(q) || false;
        if (!matchesIp && !matchesPort && !matchesProto && !matchesInfo && !matchesPayload) {
          return false;
        }
      }
      return true;
    });
  }, [packets, filterQuery, protocolFilter, cleartextOnly]);

  // Protocol badge color
  const getProtocolBadge = (proto: string) => {
    switch (proto) {
      case 'HTTP': return 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30';
      case 'DNS': return 'bg-cyan-500/20 text-cyan-300 border-cyan-500/30';
      case 'HTTPS/TLS': return 'bg-purple-500/20 text-purple-300 border-purple-500/30';
      case 'FTP': return 'bg-amber-500/20 text-amber-300 border-amber-500/30';
      case 'TELNET': return 'bg-rose-500/20 text-rose-300 border-rose-500/30';
      case 'TCP': return 'bg-indigo-500/20 text-indigo-300 border-indigo-500/30';
      case 'UDP': return 'bg-blue-500/20 text-blue-300 border-blue-500/30';
      case 'ARP': return 'bg-orange-500/20 text-orange-300 border-orange-500/30';
      default: return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  // Generate Hex & ASCII dump representation (16 bytes per line)
  const renderHexDump = (bytes: Uint8Array) => {
    const lines: { offset: string; hex: string; ascii: string }[] = [];
    const len = Math.min(bytes.length, 1024); // Cap display for performance

    for (let i = 0; i < len; i += 16) {
      const offset = i.toString(16).padStart(4, '0');
      let hexPart = '';
      let asciiPart = '';

      for (let j = 0; j < 16; j++) {
        if (i + j < len) {
          const b = bytes[i + j];
          hexPart += b.toString(16).padStart(2, '0') + ' ';
          asciiPart += b >= 32 && b <= 126 ? String.fromCharCode(b) : '.';
        } else {
          hexPart += '   ';
        }
        if (j === 7) hexPart += ' '; // Gap between 8-byte chunks
      }

      lines.push({ offset, hex: hexPart.trimEnd(), ascii: asciiPart });
    }

    return (
      <div className="font-mono text-xs overflow-x-auto space-y-0.5 select-text p-2 bg-slate-950 rounded border border-slate-800">
        {lines.map((l, idx) => (
          <div key={idx} className="flex gap-4 hover:bg-slate-900/60 px-1 py-0.5 rounded">
            <span className="text-slate-500 select-none w-12 shrink-0">{l.offset}</span>
            <span className="text-cyan-300 shrink-0 w-80 sm:w-96">{l.hex}</span>
            <span className="text-slate-200 border-l border-slate-800 pl-3 shrink-0">{l.ascii}</span>
          </div>
        ))}
        {bytes.length > 1024 && (
          <div className="text-slate-500 italic text-[11px] pt-2">
            ... truncated {bytes.length - 1024} bytes for display performance
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      
      {/* Filter Bar */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3 flex flex-col sm:flex-row items-center justify-between gap-3">
        <div className="relative w-full sm:w-96">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter by IP, port, protocol or payload keyword..."
            value={filterQuery}
            onChange={e => setFilterQuery(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-colors font-mono"
          />
        </div>

        <div className="flex items-center gap-3 w-full sm:w-auto justify-end flex-wrap">
          {/* Protocol Filter */}
          <select
            value={protocolFilter}
            onChange={e => setProtocolFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-indigo-500"
          >
            <option value="all">All Protocols</option>
            <option value="HTTP">HTTP</option>
            <option value="DNS">DNS</option>
            <option value="HTTPS/TLS">HTTPS/TLS</option>
            <option value="FTP">FTP</option>
            <option value="TELNET">TELNET</option>
            <option value="TCP">TCP</option>
            <option value="UDP">UDP</option>
          </select>

          {/* Cleartext Only Toggle */}
          <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer select-none">
            <input
              type="checkbox"
              checked={cleartextOnly}
              onChange={e => setCleartextOnly(e.target.checked)}
              className="rounded bg-slate-950 border-slate-700 text-amber-500 focus:ring-0 focus:ring-offset-0"
            />
            <span className="flex items-center gap-1 text-amber-300 font-medium">
              <LockOpen className="w-3.5 h-3.5" />
              Cleartext only
            </span>
          </label>
        </div>
      </div>

      {/* Main Split: Packet Table Top, Packet Inspector Bottom */}
      <div className="space-y-4">
        
        {/* Packets Table */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
          <div className="max-h-80 overflow-y-auto overflow-x-auto scrollbar-thin">
            <table className="w-full text-xs text-left">
              <thead className="bg-slate-950/80 sticky top-0 z-10 border-b border-slate-800 text-[10px] font-mono text-slate-400 uppercase tracking-wider">
                <tr>
                  <th className="py-2.5 px-3 w-16">No.</th>
                  <th className="py-2.5 px-3 w-20">Time</th>
                  <th className="py-2.5 px-3 w-36">Source</th>
                  <th className="py-2.5 px-3 w-36">Destination</th>
                  <th className="py-2.5 px-3 w-24">Protocol</th>
                  <th className="py-2.5 px-3 w-16 text-right">Length</th>
                  <th className="py-2.5 px-3">Info</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/40 font-mono">
                {filteredPackets.map(pkt => {
                  const isSelected = selectedPacket?.id === pkt.id;

                  return (
                    <tr
                      key={pkt.id}
                      onClick={() => onSelectPacket(pkt.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-indigo-950/70 text-white font-semibold'
                          : 'hover:bg-slate-800/50 text-slate-300'
                      }`}
                    >
                      <td className="py-2 px-3 text-slate-500">{pkt.id}</td>
                      <td className="py-2 px-3 text-slate-400">{pkt.relativeTime}s</td>
                      <td className="py-2 px-3 text-cyan-300 truncate max-w-[140px]" title={pkt.sourceIp}>
                        {pkt.sourceIp}{pkt.sourcePort ? `:${pkt.sourcePort}` : ''}
                      </td>
                      <td className="py-2 px-3 text-slate-300 truncate max-w-[140px]" title={pkt.destIp}>
                        {pkt.destIp}{pkt.destPort ? `:${pkt.destPort}` : ''}
                      </td>
                      <td className="py-2 px-3">
                        <span className={`inline-block px-1.5 py-0.2 rounded text-[10px] font-bold border ${getProtocolBadge(pkt.protocol)}`}>
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="py-2 px-3 text-right text-slate-400">
                        {pkt.originalLength || pkt.captureLength}
                      </td>
                      <td className="py-2 px-3 truncate max-w-[320px] text-slate-200" title={pkt.info}>
                        <div className="flex items-center gap-1.5">
                          {pkt.isCleartext && (
                            <span title="Contains unencrypted payload data">
                              <LockOpen className="w-3 h-3 text-amber-400 inline shrink-0" />
                            </span>
                          )}
                          <span className="truncate">{pkt.info}</span>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="bg-slate-950 px-3 py-2 border-t border-slate-800 text-[11px] text-slate-500 font-mono flex justify-between">
            <span>Showing {filteredPackets.length} of {packets.length} packets</span>
            <span>Click any packet to inspect headers and raw payload</span>
          </div>
        </div>

        {/* Selected Packet Deep Inspection Panel */}
        {selectedPacket && (
          <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm space-y-4">
            
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
              <div>
                <h4 className="text-sm font-bold text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-indigo-400" />
                  <span>Deep Packet Inspector — Frame #{selectedPacket.id}</span>
                </h4>
                <p className="text-xs text-slate-400 font-mono mt-0.5">
                  Timestamp: {selectedPacket.relativeTime}s • {selectedPacket.originalLength} bytes on wire • Protocol: {selectedPacket.protocol}
                </p>
              </div>

              {selectedPacket.isCleartext && (
                <div className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-amber-500/10 border border-amber-500/30 text-amber-300 text-xs font-semibold">
                  <LockOpen className="w-3.5 h-3.5" />
                  <span>Cleartext Payload Extracted</span>
                </div>
              )}
            </div>

            {/* Layer Breakdown Sections */}
            <div className="space-y-2">
              
              {/* Layer 2: Ethernet Frame */}
              <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-xs">
                <button
                  onClick={() => setExpandedSection(expandedSection === 'l2' ? null : 'l2')}
                  className="w-full px-3 py-2 text-left font-medium text-slate-300 flex items-center justify-between hover:bg-slate-900/50"
                >
                  <span className="flex items-center gap-2">
                    {expandedSection === 'l2' ? <ChevronDown className="w-4 h-4 text-indigo-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <span className="font-semibold text-white">Ethernet II</span>
                    <span className="font-mono text-slate-400 text-[11px]">
                      Src: {selectedPacket.sourceMac || 'N/A'}, Dst: {selectedPacket.destMac || 'N/A'}
                    </span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">EtherType {selectedPacket.etherType}</span>
                </button>

                {expandedSection === 'l2' && (
                  <div className="px-4 py-2.5 border-t border-slate-800/80 bg-slate-950/60 font-mono text-[11px] space-y-1 text-slate-300">
                    <div>Destination MAC: <span className="text-cyan-300">{selectedPacket.destMac}</span></div>
                    <div>Source MAC: <span className="text-cyan-300">{selectedPacket.sourceMac}</span></div>
                    <div>Ethernet Type: <span className="text-slate-400">{selectedPacket.etherType} (IPv4 / ARP)</span></div>
                  </div>
                )}
              </div>

              {/* Layer 3: Internet Protocol (IPv4) */}
              <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-xs">
                <button
                  onClick={() => setExpandedSection(expandedSection === 'l3' ? null : 'l3')}
                  className="w-full px-3 py-2 text-left font-medium text-slate-300 flex items-center justify-between hover:bg-slate-900/50"
                >
                  <span className="flex items-center gap-2">
                    {expandedSection === 'l3' ? <ChevronDown className="w-4 h-4 text-indigo-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <span className="font-semibold text-white">Internet Protocol Version 4</span>
                    <span className="font-mono text-slate-400 text-[11px]">
                      {selectedPacket.sourceIp} → {selectedPacket.destIp}
                    </span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">TTL: {selectedPacket.ttl || 64}</span>
                </button>

                {expandedSection === 'l3' && (
                  <div className="px-4 py-2.5 border-t border-slate-800/80 bg-slate-950/60 font-mono text-[11px] space-y-1 text-slate-300">
                    <div>Source IP: <span className="text-cyan-300 font-semibold">{selectedPacket.sourceIp}</span></div>
                    <div>Destination IP: <span className="text-cyan-300 font-semibold">{selectedPacket.destIp}</span></div>
                    <div>Time to Live (TTL): <span className="text-slate-400">{selectedPacket.ttl}</span></div>
                    <div>Protocol: <span className="text-slate-400">{selectedPacket.transportProtocol || selectedPacket.protocol}</span></div>
                  </div>
                )}
              </div>

              {/* Layer 4: Transmission Control Protocol / UDP */}
              {selectedPacket.transportProtocol && (
                <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-xs">
                  <button
                    onClick={() => setExpandedSection(expandedSection === 'l4' ? null : 'l4')}
                    className="w-full px-3 py-2 text-left font-medium text-slate-300 flex items-center justify-between hover:bg-slate-900/50"
                  >
                    <span className="flex items-center gap-2">
                      {expandedSection === 'l4' ? <ChevronDown className="w-4 h-4 text-indigo-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                      <span className="font-semibold text-white">{selectedPacket.transportProtocol}</span>
                      <span className="font-mono text-slate-400 text-[11px]">
                        Src Port: {selectedPacket.sourcePort}, Dst Port: {selectedPacket.destPort}
                      </span>
                    </span>
                    {selectedPacket.tcpFlags && (
                      <span className="text-[10px] font-mono text-amber-300">
                        Flags: {[
                          selectedPacket.tcpFlags.syn ? 'SYN' : '',
                          selectedPacket.tcpFlags.ack ? 'ACK' : '',
                          selectedPacket.tcpFlags.fin ? 'FIN' : '',
                          selectedPacket.tcpFlags.rst ? 'RST' : '',
                          selectedPacket.tcpFlags.psh ? 'PSH' : '',
                        ].filter(Boolean).join(', ')}
                      </span>
                    )}
                  </button>

                  {expandedSection === 'l4' && (
                    <div className="px-4 py-2.5 border-t border-slate-800/80 bg-slate-950/60 font-mono text-[11px] space-y-1 text-slate-300">
                      <div>Source Port: <span className="text-cyan-300">{selectedPacket.sourcePort}</span></div>
                      <div>Destination Port: <span className="text-cyan-300">{selectedPacket.destPort}</span></div>
                      {selectedPacket.seqNumber !== undefined && (
                        <div>Sequence Number: <span className="text-slate-400">{selectedPacket.seqNumber}</span></div>
                      )}
                      {selectedPacket.ackNumber !== undefined && (
                        <div>Acknowledgment Number: <span className="text-slate-400">{selectedPacket.ackNumber}</span></div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Layer 7: Application Protocol Inspection */}
              <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-xs">
                <button
                  onClick={() => setExpandedSection(expandedSection === 'l7' ? null : 'l7')}
                  className="w-full px-3 py-2 text-left font-medium text-slate-300 flex items-center justify-between hover:bg-slate-900/50"
                >
                  <span className="flex items-center gap-2">
                    {expandedSection === 'l7' ? <ChevronDown className="w-4 h-4 text-indigo-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <span className="font-semibold text-white">Application Layer Payload</span>
                    <span className="font-mono text-cyan-300 text-[11px] font-bold">
                      {selectedPacket.protocol} ({selectedPacket.payloadLength} bytes)
                    </span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">Decoded View</span>
                </button>

                {expandedSection === 'l7' && (
                  <div className="px-4 py-3 border-t border-slate-800/80 bg-slate-950/80 font-mono text-xs space-y-3">
                    
                    {/* HTTP Decoded */}
                    {selectedPacket.httpDetails && (
                      <div className="space-y-2">
                        {selectedPacket.httpDetails.isRequest ? (
                          <div className="text-emerald-400 font-bold">
                            {selectedPacket.httpDetails.method} {selectedPacket.httpDetails.path} HTTP/1.1
                          </div>
                        ) : (
                          <div className="text-emerald-400 font-bold">
                            HTTP/1.1 {selectedPacket.httpDetails.status} {selectedPacket.httpDetails.statusText}
                          </div>
                        )}

                        {/* Headers */}
                        {selectedPacket.httpDetails.headers && (
                          <div className="bg-slate-900/70 p-2.5 rounded border border-slate-800/80 space-y-1 text-[11px]">
                            {Object.entries(selectedPacket.httpDetails.headers).map(([k, v]) => (
                              <div key={k}>
                                <span className="text-slate-400 capitalize">{k}:</span>{' '}
                                <span className="text-slate-200 break-all">{v}</span>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Body */}
                        {selectedPacket.httpDetails.body && (
                          <div>
                            <div className="text-[10px] uppercase text-slate-500 mb-1">Payload Body:</div>
                            <pre className="bg-slate-900 p-2.5 rounded border border-slate-800 text-[11px] text-amber-200 whitespace-pre-wrap break-all">
                              {selectedPacket.httpDetails.body}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}

                    {/* DNS Decoded */}
                    {selectedPacket.dnsDetails && (
                      <div className="space-y-2 text-[11px]">
                        <div className="text-cyan-300 font-bold">
                          DNS {selectedPacket.dnsDetails.isQuery ? 'Query' : 'Response'} (Transaction ID: 0x{selectedPacket.dnsDetails.transactionId.toString(16)})
                        </div>
                        {selectedPacket.dnsDetails.queries.map((q, idx) => (
                          <div key={idx} className="bg-slate-900 p-2 rounded border border-slate-800">
                            <span className="text-slate-400">Question #{idx + 1}:</span>{' '}
                            <span className="text-white font-semibold">{q.name}</span>{' '}
                            <span className="text-cyan-400">({q.type})</span>
                          </div>
                        ))}
                      </div>
                    )}

                    {/* FTP Decoded */}
                    {selectedPacket.ftpDetails && (
                      <div className="space-y-1 text-xs">
                        {selectedPacket.ftpDetails.isCommand ? (
                          <div>
                            FTP Command: <span className="text-amber-400 font-bold">{selectedPacket.ftpDetails.command}</span>{' '}
                            <span className="text-white">{selectedPacket.ftpDetails.argument}</span>
                          </div>
                        ) : (
                          <div>
                            FTP Response: <span className="text-emerald-400 font-bold">{selectedPacket.ftpDetails.responseCode}</span>{' '}
                            <span className="text-slate-200">{selectedPacket.ftpDetails.responseMessage}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Telnet Decoded */}
                    {selectedPacket.telnetDetails && (
                      <div>
                        <div className="text-[10px] uppercase text-slate-500 mb-1">Telnet Stream Text:</div>
                        <pre className="bg-slate-900 p-2.5 rounded border border-slate-800 text-[11px] text-emerald-300 whitespace-pre-wrap">
                          {selectedPacket.telnetDetails.text}
                        </pre>
                      </div>
                    )}

                    {/* Fallback payload text */}
                    {!selectedPacket.httpDetails && !selectedPacket.dnsDetails && !selectedPacket.ftpDetails && !selectedPacket.telnetDetails && (
                      <div>
                        {selectedPacket.payloadText ? (
                          <pre className="bg-slate-900 p-2.5 rounded border border-slate-800 text-[11px] text-slate-300 whitespace-pre-wrap break-all">
                            {selectedPacket.payloadText}
                          </pre>
                        ) : (
                          <span className="text-slate-500 italic">No application layer data present in this frame.</span>
                        )}
                      </div>
                    )}

                  </div>
                )}
              </div>

              {/* Raw Hex & ASCII Dump */}
              <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden text-xs">
                <button
                  onClick={() => setExpandedSection(expandedSection === 'hex' ? null : 'hex')}
                  className="w-full px-3 py-2 text-left font-medium text-slate-300 flex items-center justify-between hover:bg-slate-900/50"
                >
                  <span className="flex items-center gap-2">
                    {expandedSection === 'hex' ? <ChevronDown className="w-4 h-4 text-indigo-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                    <Binary className="w-4 h-4 text-cyan-400" />
                    <span className="font-semibold text-white">Raw Packet Hex &amp; ASCII Dump</span>
                  </span>
                  <span className="text-[10px] font-mono text-slate-500">16 bytes / line</span>
                </button>

                {expandedSection === 'hex' && (
                  <div className="p-3 border-t border-slate-800/80 bg-slate-950">
                    {renderHexDump(selectedPacket.rawBytes)}
                  </div>
                )}
              </div>

            </div>

          </div>
        )}

      </div>

    </div>
  );
};
