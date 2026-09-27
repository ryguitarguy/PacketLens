import { Packet } from '../types';

export interface PcapProgressCallback {
  (progress: { stage: string; percent: number; parsedCount: number }): void;
}

// Pre-allocated static table of all 64 possible TCP flag combinations (0x00 - 0x3F)
// Avoids allocating 100,000+ individual flag objects in memory!
const TCP_FLAGS_TABLE: Array<{
  urg: boolean;
  ack: boolean;
  psh: boolean;
  rst: boolean;
  syn: boolean;
  fin: boolean;
}> = [];

for (let f = 0; f < 64; f++) {
  TCP_FLAGS_TABLE[f] = Object.freeze({
    urg: (f & 0x20) !== 0,
    ack: (f & 0x10) !== 0,
    psh: (f & 0x08) !== 0,
    rst: (f & 0x04) !== 0,
    syn: (f & 0x02) !== 0,
    fin: (f & 0x01) !== 0,
  });
}

// Pre-cached summary descriptions for common TCP flag masks
const TCP_FLAGS_SUMMARY: string[] = [];
for (let f = 0; f < 64; f++) {
  const parts: string[] = [];
  if (f & 0x02) parts.push('SYN');
  if (f & 0x10) parts.push('ACK');
  if (f & 0x01) parts.push('FIN');
  if (f & 0x04) parts.push('RST');
  if (f & 0x08) parts.push('PSH');
  if (f & 0x20) parts.push('URG');
  TCP_FLAGS_SUMMARY[f] = parts.join(', ') || 'TCP';
}

export class PcapParser {
  private view: DataView;
  private bytes: Uint8Array;
  private isLittleEndian: boolean = true;
  private isNanosecond: boolean = false;
  private isPcapNg: boolean = false;

  // High-performance string interning caches: captures typically have < 100 distinct IPs and MACs
  private ipCache: Map<number, string> = new Map();
  private macCache: Map<string, string> = new Map();
  private textDecoder = new TextDecoder('latin1'); // 1:1 single-byte decode, fast & zero copy

  constructor(arrayBuffer: ArrayBuffer) {
    this.bytes = new Uint8Array(arrayBuffer);
    this.view = new DataView(arrayBuffer);
  }

  public static parse(
    arrayBuffer: ArrayBuffer,
    maxPackets: number = 250000
  ): { packets: Packet[]; totalCount: number; truncated: boolean } {
    const parser = new PcapParser(arrayBuffer);
    return parser.parseSync(maxPackets);
  }

  public static async parseAsync(
    arrayBuffer: ArrayBuffer,
    onProgress?: PcapProgressCallback,
    shouldAbort?: () => boolean,
    maxPackets: number = 250000
  ): Promise<{ packets: Packet[]; totalCount: number; truncated: boolean }> {
    const parser = new PcapParser(arrayBuffer);
    return parser.parseAsyncInternal(onProgress, shouldAbort, maxPackets);
  }

  public parseSync(maxPackets: number = 250000): { packets: Packet[]; totalCount: number; truncated: boolean } {
    if (this.bytes.length < 24) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    const magic = this.view.getUint32(0, false);

    if (magic === 0xa1b2c3d4) {
      this.isLittleEndian = false;
      this.isNanosecond = false;
      return this.parseClassicPcapSync(maxPackets);
    } else if (magic === 0xd4c3b2a1) {
      this.isLittleEndian = true;
      this.isNanosecond = false;
      return this.parseClassicPcapSync(maxPackets);
    } else if (magic === 0xa1b23c4d) {
      this.isLittleEndian = false;
      this.isNanosecond = true;
      return this.parseClassicPcapSync(maxPackets);
    } else if (magic === 0x4d3cb2a1) {
      this.isLittleEndian = true;
      this.isNanosecond = true;
      return this.parseClassicPcapSync(maxPackets);
    } else if (magic === 0x0a0d0d0a) {
      this.isPcapNg = true;
      return this.parsePcapNgSync(maxPackets);
    } else {
      try {
        this.isLittleEndian = true;
        return this.parseClassicPcapSync(maxPackets);
      } catch {
        throw new Error('Unrecognized PCAP format. Supported formats: .pcap (libpcap) and .pcapng.');
      }
    }
  }

  private async parseAsyncInternal(
    onProgress?: PcapProgressCallback,
    shouldAbort?: () => boolean,
    maxPackets: number = 250000
  ): Promise<{ packets: Packet[]; totalCount: number; truncated: boolean }> {
    if (this.bytes.length < 24) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    const magic = this.view.getUint32(0, false);

    if (magic === 0xa1b2c3d4) {
      this.isLittleEndian = false;
      this.isNanosecond = false;
      return this.parseClassicPcapAsync(onProgress, shouldAbort, maxPackets);
    } else if (magic === 0xd4c3b2a1) {
      this.isLittleEndian = true;
      this.isNanosecond = false;
      return this.parseClassicPcapAsync(onProgress, shouldAbort, maxPackets);
    } else if (magic === 0xa1b23c4d) {
      this.isLittleEndian = false;
      this.isNanosecond = true;
      return this.parseClassicPcapAsync(onProgress, shouldAbort, maxPackets);
    } else if (magic === 0x4d3cb2a1) {
      this.isLittleEndian = true;
      this.isNanosecond = true;
      return this.parseClassicPcapAsync(onProgress, shouldAbort, maxPackets);
    } else if (magic === 0x0a0d0d0a) {
      this.isPcapNg = true;
      return this.parsePcapNgAsync(onProgress, shouldAbort, maxPackets);
    } else {
      try {
        this.isLittleEndian = true;
        return this.parseClassicPcapAsync(onProgress, shouldAbort, maxPackets);
      } catch {
        throw new Error('Unrecognized PCAP format. Supported formats: .pcap (libpcap) and .pcapng.');
      }
    }
  }

  private parseClassicPcapSync(maxPackets: number): { packets: Packet[]; totalCount: number; truncated: boolean } {
    const packets: Packet[] = [];
    const linkType = this.view.getUint32(20, this.isLittleEndian);
    let offset = 24;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let truncated = false;

    while (offset + 16 <= this.bytes.length) {
      const tsSec = this.view.getUint32(offset, this.isLittleEndian);
      const tsSub = this.view.getUint32(offset + 4, this.isLittleEndian);
      const inclLen = this.view.getUint32(offset + 8, this.isLittleEndian);
      const origLen = this.view.getUint32(offset + 12, this.isLittleEndian);
      offset += 16;

      if (inclLen > 65535 || offset + inclLen > this.bytes.length) {
        break;
      }

      if (packets.length >= maxPackets) {
        truncated = true;
        offset += inclLen;
        packetIndex++;
        continue;
      }

      const timestamp = tsSec + (this.isNanosecond ? tsSub / 1e9 : tsSub / 1e6);
      if (baseTime === null) baseTime = timestamp;
      const relativeTime = Math.max(0, timestamp - baseTime);

      const packetData = this.bytes.subarray(offset, offset + inclLen);
      offset += inclLen;

      try {
        const decoded = this.decodePacketData(packetIndex, timestamp, relativeTime, packetData, origLen, linkType);
        packets.push(decoded);
      } catch (e) {
        console.warn(`Error decoding packet #${packetIndex}:`, e);
      }
      packetIndex++;
    }

    return { packets, totalCount: packetIndex - 1, truncated };
  }

  private async parseClassicPcapAsync(
    onProgress?: PcapProgressCallback,
    shouldAbort?: () => boolean,
    maxPackets: number = 250000
  ): Promise<{ packets: Packet[]; totalCount: number; truncated: boolean }> {
    const packets: Packet[] = [];
    const linkType = this.view.getUint32(20, this.isLittleEndian);
    let offset = 24;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let truncated = false;
    const totalBytes = this.bytes.length;

    let lastYieldTime = performance.now();

    while (offset + 16 <= totalBytes) {
      if (shouldAbort && shouldAbort()) {
        throw new Error('Analysis cancelled by user');
      }

      const now = performance.now();
      // Yield every 18ms or every 2,500 packets to keep browser perfectly fluid
      if (now - lastYieldTime > 18 || packetIndex % 2500 === 0) {
        const percent = Math.min(99, Math.round((offset / totalBytes) * 100));
        onProgress?.({ stage: 'parsing', percent, parsedCount: packets.length });
        await new Promise<void>(resolve => setTimeout(resolve, 0));
        lastYieldTime = performance.now();
      }

      const tsSec = this.view.getUint32(offset, this.isLittleEndian);
      const tsSub = this.view.getUint32(offset + 4, this.isLittleEndian);
      const inclLen = this.view.getUint32(offset + 8, this.isLittleEndian);
      const origLen = this.view.getUint32(offset + 12, this.isLittleEndian);
      offset += 16;

      if (inclLen > 65535 || offset + inclLen > totalBytes) {
        break;
      }

      if (packets.length >= maxPackets) {
        truncated = true;
        offset += inclLen;
        packetIndex++;
        continue;
      }

      const timestamp = tsSec + (this.isNanosecond ? tsSub / 1e9 : tsSub / 1e6);
      if (baseTime === null) baseTime = timestamp;
      const relativeTime = Math.max(0, timestamp - baseTime);

      const packetData = this.bytes.subarray(offset, offset + inclLen);
      offset += inclLen;

      try {
        const decoded = this.decodePacketData(packetIndex, timestamp, relativeTime, packetData, origLen, linkType);
        packets.push(decoded);
      } catch (e) {
        console.warn(`Error decoding packet #${packetIndex}:`, e);
      }
      packetIndex++;
    }

    onProgress?.({ stage: 'parsing', percent: 100, parsedCount: packets.length });
    return { packets, totalCount: packetIndex - 1, truncated };
  }

  private parsePcapNgSync(maxPackets: number): { packets: Packet[]; totalCount: number; truncated: boolean } {
    const packets: Packet[] = [];
    let offset = 0;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let truncated = false;

    while (offset + 8 <= this.bytes.length) {
      const blockType = this.view.getUint32(offset, true);
      const blockTotalLength = this.view.getUint32(offset + 4, true);

      if (blockTotalLength < 12 || offset + blockTotalLength > this.bytes.length) {
        break;
      }

      if (blockType === 0x00000006) {
        if (packets.length >= maxPackets) {
          truncated = true;
          packetIndex++;
        } else if (offset + 28 <= this.bytes.length) {
          const tsHigh = this.view.getUint32(offset + 12, true);
          const tsLow = this.view.getUint32(offset + 16, true);
          const capLen = this.view.getUint32(offset + 20, true);
          const origLen = this.view.getUint32(offset + 24, true);

          const rawTs = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
          const timestamp = Number(rawTs) / 1e6;
          if (baseTime === null) baseTime = timestamp;
          const relativeTime = Math.max(0, timestamp - baseTime);

          const packetOffset = offset + 28;
          if (packetOffset + capLen <= offset + blockTotalLength) {
            const packetData = this.bytes.subarray(packetOffset, packetOffset + capLen);
            const decoded = this.decodePacketData(packetIndex, timestamp, relativeTime, packetData, origLen, 1);
            packets.push(decoded);
            packetIndex++;
          }
        }
      }

      offset += blockTotalLength;
    }

    return { packets, totalCount: packetIndex - 1, truncated };
  }

  private async parsePcapNgAsync(
    onProgress?: PcapProgressCallback,
    shouldAbort?: () => boolean,
    maxPackets: number = 250000
  ): Promise<{ packets: Packet[]; totalCount: number; truncated: boolean }> {
    const packets: Packet[] = [];
    let offset = 0;
    let packetIndex = 1;
    let baseTime: number | null = null;
    let truncated = false;
    const totalBytes = this.bytes.length;
    let lastYieldTime = performance.now();

    while (offset + 8 <= totalBytes) {
      if (shouldAbort && shouldAbort()) {
        throw new Error('Analysis cancelled by user');
      }

      const now = performance.now();
      if (now - lastYieldTime > 18 || packetIndex % 2500 === 0) {
        const percent = Math.min(99, Math.round((offset / totalBytes) * 100));
        onProgress?.({ stage: 'parsing', percent, parsedCount: packets.length });
        await new Promise<void>(resolve => setTimeout(resolve, 0));
        lastYieldTime = performance.now();
      }

      const blockType = this.view.getUint32(offset, true);
      const blockTotalLength = this.view.getUint32(offset + 4, true);

      if (blockTotalLength < 12 || offset + blockTotalLength > totalBytes) {
        break;
      }

      if (blockType === 0x00000006) {
        if (packets.length >= maxPackets) {
          truncated = true;
          packetIndex++;
        } else if (offset + 28 <= totalBytes) {
          const tsHigh = this.view.getUint32(offset + 12, true);
          const tsLow = this.view.getUint32(offset + 16, true);
          const capLen = this.view.getUint32(offset + 20, true);
          const origLen = this.view.getUint32(offset + 24, true);

          const rawTs = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
          const timestamp = Number(rawTs) / 1e6;
          if (baseTime === null) baseTime = timestamp;
          const relativeTime = Math.max(0, timestamp - baseTime);

          const packetOffset = offset + 28;
          if (packetOffset + capLen <= offset + blockTotalLength) {
            const packetData = this.bytes.subarray(packetOffset, packetOffset + capLen);
            const decoded = this.decodePacketData(packetIndex, timestamp, relativeTime, packetData, origLen, 1);
            packets.push(decoded);
            packetIndex++;
          }
        }
      }

      offset += blockTotalLength;
    }

    onProgress?.({ stage: 'parsing', percent: 100, parsedCount: packets.length });
    return { packets, totalCount: packetIndex - 1, truncated };
  }

  private decodePacketData(
    id: number,
    timestamp: number,
    relativeTime: number,
    data: Uint8Array,
    originalLength: number,
    linkType: number
  ): Packet {
    const packet: Packet = {
      id,
      timestamp,
      relativeTime: Number(relativeTime.toFixed(4)),
      captureLength: data.length,
      originalLength,
      linkType,
      sourceIp: '0.0.0.0',
      destIp: '0.0.0.0',
      protocol: 'OTHER',
      info: 'Raw Frame',
      payloadLength: 0,
      rawBytes: data,
    };

    if (data.length < 14) {
      return packet;
    }

    // Ethernet frame (LinkType 1)
    let ethOffset = 0;
    packet.destMac = this.formatMac(data.subarray(0, 6));
    packet.sourceMac = this.formatMac(data.subarray(6, 12));
    let etherType = (data[12] << 8) | data[13];
    ethOffset = 14;

    // Handle 802.1Q VLAN Tag
    if (etherType === 0x8100 && data.length >= 18) {
      etherType = (data[16] << 8) | data[17];
      ethOffset = 18;
    }

    packet.etherType = `0x${etherType.toString(16).padStart(4, '0').toUpperCase()}`;

    // IPv4
    if (etherType === 0x0800 && data.length >= ethOffset + 20) {
      packet.ipVersion = 4;
      const ipHeaderStart = ethOffset;
      const ihl = (data[ipHeaderStart] & 0x0f) * 4;
      packet.ttl = data[ipHeaderStart + 8];
      const ipProtocol = data[ipHeaderStart + 9];

      // Fast IP caching by 32-bit int
      const srcInt = (data[ipHeaderStart + 12] << 24) | (data[ipHeaderStart + 13] << 16) | (data[ipHeaderStart + 14] << 8) | data[ipHeaderStart + 15];
      const dstInt = (data[ipHeaderStart + 16] << 24) | (data[ipHeaderStart + 17] << 16) | (data[ipHeaderStart + 18] << 8) | data[ipHeaderStart + 19];
      
      packet.sourceIp = this.getOrCacheIp(srcInt, data[ipHeaderStart + 12], data[ipHeaderStart + 13], data[ipHeaderStart + 14], data[ipHeaderStart + 15]);
      packet.destIp = this.getOrCacheIp(dstInt, data[ipHeaderStart + 16], data[ipHeaderStart + 17], data[ipHeaderStart + 18], data[ipHeaderStart + 19]);

      const transportOffset = ipHeaderStart + ihl;

      // TCP
      if (ipProtocol === 6 && data.length >= transportOffset + 20) {
        packet.transportProtocol = 'TCP';
        packet.protocol = 'TCP';
        packet.sourcePort = (data[transportOffset] << 8) | data[transportOffset + 1];
        packet.destPort = (data[transportOffset + 2] << 8) | data[transportOffset + 3];

        const seq = (data[transportOffset + 4] << 24) | (data[transportOffset + 5] << 16) | (data[transportOffset + 6] << 8) | data[transportOffset + 7];
        const ack = (data[transportOffset + 8] << 24) | (data[transportOffset + 9] << 16) | (data[transportOffset + 10] << 8) | data[transportOffset + 11];
        packet.seqNumber = seq >>> 0;
        packet.ackNumber = ack >>> 0;

        const dataOffset = ((data[transportOffset + 12] >> 4) & 0x0f) * 4;
        const flagsByte = data[transportOffset + 13] & 0x3f;
        // Reuse pre-allocated frozen flag object
        packet.tcpFlags = TCP_FLAGS_TABLE[flagsByte];

        const payloadStart = transportOffset + dataOffset;
        if (payloadStart <= data.length) {
          const payload = data.subarray(payloadStart);
          packet.payloadLength = payload.length;
          packet.payloadBytes = payload;
          this.decodeApplicationLayer(packet);
        }

        if (packet.info === 'Raw Frame') {
          const flagsStr = TCP_FLAGS_SUMMARY[flagsByte];
          packet.info = `${packet.sourcePort} → ${packet.destPort} [${flagsStr}] Seq=${packet.seqNumber} Ack=${packet.ackNumber} Len=${packet.payloadLength}`;
        }
      } 
      // UDP
      else if (ipProtocol === 17 && data.length >= transportOffset + 8) {
        packet.transportProtocol = 'UDP';
        packet.protocol = 'UDP';
        packet.sourcePort = (data[transportOffset] << 8) | data[transportOffset + 1];
        packet.destPort = (data[transportOffset + 2] << 8) | data[transportOffset + 3];
        const udpLen = (data[transportOffset + 4] << 8) | data[transportOffset + 5];

        const payloadStart = transportOffset + 8;
        if (payloadStart <= data.length) {
          const payload = data.subarray(payloadStart, Math.min(data.length, payloadStart + Math.max(0, udpLen - 8)));
          packet.payloadLength = payload.length;
          packet.payloadBytes = payload;
          this.decodeApplicationLayer(packet);
        }

        if (packet.info === 'Raw Frame') {
          packet.info = `${packet.sourcePort} → ${packet.destPort} Len=${packet.payloadLength}`;
        }
      } 
      // ICMP
      else if (ipProtocol === 1 && data.length >= transportOffset + 8) {
        packet.transportProtocol = 'ICMP';
        packet.protocol = 'ICMP';
        const type = data[transportOffset];
        const code = data[transportOffset + 1];
        const icmpDesc = type === 8 ? 'Echo (ping) request' : type === 0 ? 'Echo (ping) reply' : type === 3 ? 'Destination unreachable' : `Type ${type}`;
        packet.info = `${icmpDesc} id=0x${((data[transportOffset + 4] << 8) | data[transportOffset + 5]).toString(16)} code=${code}`;
      }
    } 
    // ARP
    else if (etherType === 0x0806 && data.length >= ethOffset + 28) {
      packet.protocol = 'ARP';
      packet.transportProtocol = 'ARP';
      const opcode = (data[ethOffset + 6] << 8) | data[ethOffset + 7];
      const s0 = data[ethOffset + 14], s1 = data[ethOffset + 15], s2 = data[ethOffset + 16], s3 = data[ethOffset + 17];
      const t0 = data[ethOffset + 24], t1 = data[ethOffset + 25], t2 = data[ethOffset + 26], t3 = data[ethOffset + 27];
      const srcInt = (s0 << 24) | (s1 << 16) | (s2 << 8) | s3;
      const dstInt = (t0 << 24) | (t1 << 16) | (t2 << 8) | t3;
      
      const senderIp = this.getOrCacheIp(srcInt, s0, s1, s2, s3);
      const targetIp = this.getOrCacheIp(dstInt, t0, t1, t2, t3);
      packet.sourceIp = senderIp;
      packet.destIp = targetIp;
      packet.info = opcode === 1 ? `Who has ${targetIp}? Tell ${senderIp}` : `${senderIp} is at ${this.formatMac(data.subarray(ethOffset + 8, ethOffset + 14))}`;
    }

    return packet;
  }

  // Fast string interning for IP addresses
  private getOrCacheIp(intVal: number, o1: number, o2: number, o3: number, o4: number): string {
    let str = this.ipCache.get(intVal);
    if (!str) {
      str = `${o1}.${o2}.${o3}.${o4}`;
      if (this.ipCache.size < 2048) {
        this.ipCache.set(intVal, str);
      }
    }
    return str;
  }

  // Direct byte-level signature check for HTTP requests or responses
  private isHttpSignature(p: Uint8Array): boolean {
    if (p.length < 4) return false;
    const b0 = p[0], b1 = p[1], b2 = p[2], b3 = p[3];

    // 'GET '
    if (b0 === 0x47 && b1 === 0x45 && b2 === 0x54 && b3 === 0x20) return true;
    // 'POST'
    if (b0 === 0x50 && b1 === 0x4f && b2 === 0x53 && b3 === 0x54) return true;
    // 'PUT '
    if (b0 === 0x50 && b1 === 0x55 && b2 === 0x54 && b3 === 0x20) return true;
    // 'HTTP'
    if (b0 === 0x48 && b1 === 0x54 && b2 === 0x54 && b3 === 0x50) return true;
    // 'HEAD'
    if (b0 === 0x48 && b1 === 0x45 && b2 === 0x41 && b3 === 0x44) return true;
    // 'DELE' (DELETE)
    if (b0 === 0x44 && b1 === 0x45 && b2 === 0x4c && b3 === 0x45) return true;
    // 'OPTI' (OPTIONS)
    if (b0 === 0x4f && b1 === 0x50 && b2 === 0x54 && b3 === 0x49) return true;
    // 'PATC' (PATCH)
    if (b0 === 0x50 && b1 === 0x41 && b2 === 0x54 && b3 === 0x43) return true;

    return false;
  }

  private decodeApplicationLayer(packet: Packet): void {
    const payload = packet.payloadBytes;
    if (!payload || payload.length === 0) return;

    const srcPort = packet.sourcePort || 0;
    const dstPort = packet.destPort || 0;

    // DNS (Port 53)
    if (srcPort === 53 || dstPort === 53) {
      this.decodeDns(packet);
      return;
    }

    // TLS / HTTPS (Port 443 or TLS record signature 0x16 0x03)
    if (srcPort === 443 || dstPort === 443 || (payload.length >= 2 && payload[0] === 0x16 && payload[1] === 0x03)) {
      this.decodeTls(packet);
      return;
    }

    // Fast check for HTTP: port check OR byte signature check
    const isHttpPort = srcPort === 80 || dstPort === 80 || srcPort === 8080 || dstPort === 8080 || srcPort === 3000 || dstPort === 3000;
    const hasHttpSig = this.isHttpSignature(payload);

    if (hasHttpSig || (isHttpPort && payload.length > 8 && this.isHttpSignature(payload))) {
      packet.payloadText = this.bytesToAscii(payload, 4096);
      if (this.decodeHttp(packet)) {
        return;
      }
    }

    // FTP (Port 21)
    if (srcPort === 21 || dstPort === 21) {
      packet.payloadText = this.bytesToAscii(payload, 2048);
      this.decodeFtp(packet);
      return;
    }

    // Telnet (Port 23)
    if (srcPort === 23 || dstPort === 23) {
      this.decodeTelnet(packet);
      return;
    }

    // SMTP (Port 25, 587)
    if (srcPort === 25 || dstPort === 25 || srcPort === 587 || dstPort === 587) {
      packet.payloadText = this.bytesToAscii(payload, 2048);
      this.decodeSmtp(packet);
      return;
    }
  }

  private decodeHttp(packet: Packet): boolean {
    const text = packet.payloadText || '';
    const lineEndIdx = text.indexOf('\r\n');
    if (lineEndIdx === -1) return false;

    const firstLine = text.substring(0, lineEndIdx);
    const isRequest = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/1\.[01]/.test(firstLine);
    const isResponse = /^HTTP\/1\.[01]\s+(\d{3})\s*(.*)/.test(firstLine);

    if (!isRequest && !isResponse) {
      return false;
    }

    packet.protocol = 'HTTP';
    packet.isCleartext = true;

    const lines = text.split('\r\n');
    const headers: Record<string, string> = {};
    let lineIdx = 1;
    for (; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      if (line === '') {
        lineIdx++;
        break;
      }
      const colonIdx = line.indexOf(':');
      if (colonIdx > 0) {
        const key = line.substring(0, colonIdx).trim().toLowerCase();
        const value = line.substring(colonIdx + 1).trim();
        headers[key] = value;
      }
    }

    const body = lines.slice(lineIdx).join('\r\n');

    if (isRequest) {
      const parts = firstLine.split(' ');
      const method = parts[0];
      const path = parts[1];
      packet.httpDetails = {
        isRequest: true,
        method,
        path,
        headers,
        body,
        contentType: headers['content-type'],
      };
      packet.info = `${method} ${path} ${headers['host'] ? `[Host: ${headers['host']}]` : ''}`;
    } else {
      const match = firstLine.match(/^HTTP\/1\.[01]\s+(\d{3})\s*(.*)/);
      const status = match ? parseInt(match[1], 10) : 200;
      const statusText = match ? match[2] : 'OK';
      packet.httpDetails = {
        isRequest: false,
        status,
        statusText,
        headers,
        body,
        contentType: headers['content-type'],
      };
      packet.info = `HTTP/1.1 ${status} ${statusText} (${headers['content-type'] || 'body'})`;
    }

    return true;
  }

  private decodeDns(packet: Packet): void {
    const payload = packet.payloadBytes;
    if (!payload || payload.length < 12) return;

    packet.protocol = 'DNS';
    packet.isCleartext = true;

    const txId = (payload[0] << 8) | payload[1];
    const flags = (payload[2] << 8) | payload[3];
    const isQuery = (flags & 0x8000) === 0;
    const qdCount = (payload[4] << 8) | payload[5];

    const queries: { name: string; type: string }[] = [];
    const answers: { name: string; type: string; data: string }[] = [];

    let offset = 12;
    for (let i = 0; i < qdCount && offset < payload.length; i++) {
      const nameResult = this.parseDnsName(payload, offset);
      offset = nameResult.nextOffset;
      if (offset + 4 <= payload.length) {
        const qType = (payload[offset] << 8) | payload[offset + 1];
        offset += 4;
        queries.push({
          name: nameResult.name,
          type: this.dnsTypeToString(qType),
        });
      }
    }

    if (queries.length > 0) {
      const firstQ = queries[0];
      packet.info = `${isQuery ? 'Standard query' : 'Standard query response'} 0x${txId.toString(16)} ${firstQ.type} ${firstQ.name}`;
    } else {
      packet.info = `DNS 0x${txId.toString(16)} ${isQuery ? 'Query' : 'Response'}`;
    }

    packet.dnsDetails = {
      isQuery,
      transactionId: txId,
      queries,
      answers,
    };
  }

  private parseDnsName(payload: Uint8Array, startOffset: number): { name: string; nextOffset: number } {
    let offset = startOffset;
    const labels: string[] = [];
    let jumped = false;
    let nextOffset = startOffset;

    while (offset < payload.length) {
      const len = payload[offset];
      if (len === 0) {
        if (!jumped) nextOffset = offset + 1;
        break;
      }

      if ((len & 0xc0) === 0xc0) {
        if (offset + 1 >= payload.length) break;
        const pointer = ((len & 0x3f) << 8) | payload[offset + 1];
        if (!jumped) nextOffset = offset + 2;
        jumped = true;
        offset = pointer;
        continue;
      }

      offset++;
      if (offset + len <= payload.length) {
        let label = '';
        for (let i = 0; i < len; i++) {
          label += String.fromCharCode(payload[offset + i]);
        }
        labels.push(label);
        offset += len;
      } else {
        break;
      }
    }

    if (!jumped) nextOffset = offset + 1;
    return { name: labels.join('.') || '<root>', nextOffset };
  }

  private dnsTypeToString(type: number): string {
    switch (type) {
      case 1: return 'A';
      case 28: return 'AAAA';
      case 5: return 'CNAME';
      case 15: return 'MX';
      case 16: return 'TXT';
      case 2: return 'NS';
      case 12: return 'PTR';
      case 6: return 'SOA';
      default: return `TYPE${type}`;
    }
  }

  private decodeFtp(packet: Packet): void {
    packet.protocol = 'FTP';
    packet.isCleartext = true;
    const text = (packet.payloadText || '').trim();

    if (packet.destPort === 21) {
      const spaceIdx = text.indexOf(' ');
      const cmd = spaceIdx > 0 ? text.substring(0, spaceIdx).toUpperCase() : text.toUpperCase();
      const arg = spaceIdx > 0 ? text.substring(spaceIdx + 1) : '';
      packet.ftpDetails = {
        isCommand: true,
        command: cmd,
        argument: arg,
      };
      packet.info = `FTP Command: ${cmd} ${cmd === 'PASS' ? '********' : arg}`;
    } else {
      const match = text.match(/^(\d{3})\s*(.*)/);
      const code = match ? parseInt(match[1], 10) : 0;
      const msg = match ? match[2] : text;
      packet.ftpDetails = {
        isCommand: false,
        responseCode: code,
        responseMessage: msg,
      };
      packet.info = `FTP Response: ${code} ${msg}`;
    }
  }

  private decodeTelnet(packet: Packet): void {
    packet.protocol = 'TELNET';
    packet.isCleartext = true;
    const raw = packet.payloadBytes || new Uint8Array();
    
    let cleanText = '';
    const maxLen = Math.min(raw.length, 1024);
    for (let i = 0; i < maxLen; i++) {
      if (raw[i] === 0xff) {
        i += 2;
        continue;
      }
      if (raw[i] >= 32 && raw[i] <= 126) {
        cleanText += String.fromCharCode(raw[i]);
      } else if (raw[i] === 10 || raw[i] === 13) {
        cleanText += '\n';
      }
    }

    packet.telnetDetails = {
      text: cleanText,
    };
    packet.info = `Telnet Data: ${cleanText.replace(/\n/g, ' ').substring(0, 50) || '<control characters>'}`;
  }

  private decodeSmtp(packet: Packet): void {
    packet.protocol = 'SMTP';
    packet.isCleartext = true;
    const text = (packet.payloadText || '').trim();
    packet.info = `SMTP: ${text.substring(0, 60)}`;
  }

  private decodeTls(packet: Packet): void {
    packet.protocol = 'HTTPS/TLS';
    const payload = packet.payloadBytes;
    if (!payload || payload.length < 5) return;

    const contentType = payload[0];
    if (contentType === 0x16) {
      const handshakeType = payload[5];
      if (handshakeType === 1) {
        const sni = this.extractTlsSni(payload);
        packet.tlsDetails = {
          handshakeType: 'Client Hello',
          sni: sni || undefined,
        };
        packet.info = `TLS Client Hello ${sni ? `[SNI: ${sni}]` : ''}`;
        return;
      } else if (handshakeType === 2) {
        packet.tlsDetails = { handshakeType: 'Server Hello' };
        packet.info = 'TLS Server Hello';
        return;
      }
    }
    packet.info = 'TLS Encrypted Application Data';
  }

  private extractTlsSni(payload: Uint8Array): string | null {
    try {
      let offset = 43;
      if (offset >= payload.length) return null;
      const sessionIdLen = payload[offset];
      offset += 1 + sessionIdLen;

      if (offset + 2 > payload.length) return null;
      const cipherSuitesLen = (payload[offset] << 8) | payload[offset + 1];
      offset += 2 + cipherSuitesLen;

      if (offset + 1 > payload.length) return null;
      const compMethodsLen = payload[offset];
      offset += 1 + compMethodsLen;

      if (offset + 2 > payload.length) return null;
      const extensionsLen = (payload[offset] << 8) | payload[offset + 1];
      offset += 2;

      const extEnd = offset + extensionsLen;
      while (offset + 4 <= extEnd && offset + 4 <= payload.length) {
        const extType = (payload[offset] << 8) | payload[offset + 1];
        const extLen = (payload[offset + 2] << 8) | payload[offset + 3];
        offset += 4;

        if (extType === 0) {
          if (offset + 5 <= payload.length) {
            const nameLen = (payload[offset + 3] << 8) | payload[offset + 4];
            let name = '';
            const readEnd = Math.min(offset + 5 + nameLen, payload.length);
            for (let i = offset + 5; i < readEnd; i++) {
              name += String.fromCharCode(payload[i]);
            }
            return name;
          }
        }
        offset += extLen;
      }
    } catch {
      // Ignore
    }
    return null;
  }

  private formatMac(bytes: Uint8Array): string {
    if (bytes.length < 6) return '00:00:00:00:00:00';
    const key = `${bytes[0]}-${bytes[1]}-${bytes[2]}-${bytes[3]}-${bytes[4]}-${bytes[5]}`;
    let cached = this.macCache.get(key);
    if (!cached) {
      let s = '';
      for (let i = 0; i < 6; i++) {
        const h = bytes[i].toString(16);
        s += (h.length === 1 ? '0' + h : h) + (i < 5 ? ':' : '');
      }
      cached = s;
      if (this.macCache.size < 512) {
        this.macCache.set(key, cached);
      }
    }
    return cached;
  }

  public bytesToAscii(bytes: Uint8Array, maxLen = 4096): string {
    const len = Math.min(bytes.length, maxLen);
    if (len === 0) return '';
    try {
      return this.textDecoder.decode(bytes.subarray(0, len));
    } catch {
      let s = '';
      for (let i = 0; i < len; i++) {
        const b = bytes[i];
        s += (b >= 32 && b <= 126) || b === 10 || b === 13 || b === 9 ? String.fromCharCode(b) : '.';
      }
      return s;
    }
  }
}
