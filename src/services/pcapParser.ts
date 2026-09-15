import { Packet, ProtocolType } from '../types';

export class PcapParser {
  private view: DataView;
  private bytes: Uint8Array;
  private isLittleEndian: boolean = true;
  private isNanosecond: boolean = false;
  private isPcapNg: boolean = false;

  constructor(arrayBuffer: ArrayBuffer) {
    this.bytes = new Uint8Array(arrayBuffer);
    this.view = new DataView(arrayBuffer);
  }

  public static parse(arrayBuffer: ArrayBuffer): { packets: Packet[] } {
    const parser = new PcapParser(arrayBuffer);
    return { packets: parser.parse() };
  }

  public parse(): Packet[] {
    if (this.bytes.length < 24) {
      throw new Error('File is too small to be a valid PCAP file.');
    }

    const magic = this.view.getUint32(0, false);

    // Standard PCAP magic numbers
    if (magic === 0xa1b2c3d4) {
      this.isLittleEndian = false;
      this.isNanosecond = false;
      return this.parseClassicPcap();
    } else if (magic === 0xd4c3b2a1) {
      this.isLittleEndian = true;
      this.isNanosecond = false;
      return this.parseClassicPcap();
    } else if (magic === 0xa1b23c4d) {
      this.isLittleEndian = false;
      this.isNanosecond = true;
      return this.parseClassicPcap();
    } else if (magic === 0x4d3cb2a1) {
      this.isLittleEndian = true;
      this.isNanosecond = true;
      return this.parseClassicPcap();
    } else if (magic === 0x0a0d0d0a) {
      // PCAP Next Generation
      this.isPcapNg = true;
      return this.parsePcapNg();
    } else {
      // Attempt heuristic parsing or fallback
      try {
        this.isLittleEndian = true;
        return this.parseClassicPcap();
      } catch {
        throw new Error('Unrecognized PCAP format. Supported formats: .pcap (libpcap) and .pcapng.');
      }
    }
  }

  private parseClassicPcap(): Packet[] {
    const packets: Packet[] = [];
    const linkType = this.view.getUint32(20, this.isLittleEndian);
    let offset = 24; // Skip global header
    let packetIndex = 1;
    let baseTime: number | null = null;

    while (offset + 16 <= this.bytes.length) {
      const tsSec = this.view.getUint32(offset, this.isLittleEndian);
      const tsSub = this.view.getUint32(offset + 4, this.isLittleEndian);
      const inclLen = this.view.getUint32(offset + 8, this.isLittleEndian);
      const origLen = this.view.getUint32(offset + 12, this.isLittleEndian);
      offset += 16;

      if (inclLen > 65535 || offset + inclLen > this.bytes.length) {
        // Corrupted packet or reached EOF
        break;
      }

      const timestamp = tsSec + (this.isNanosecond ? tsSub / 1e9 : tsSub / 1e6);
      if (baseTime === null) baseTime = timestamp;
      const relativeTime = Math.max(0, timestamp - baseTime);

      const packetData = this.bytes.slice(offset, offset + inclLen);
      offset += inclLen;

      try {
        const decoded = this.decodePacketData(packetIndex, timestamp, relativeTime, packetData, origLen, linkType);
        packets.push(decoded);
        packetIndex++;
      } catch (e) {
        console.warn(`Error decoding packet #${packetIndex}:`, e);
      }
    }

    return packets;
  }

  private parsePcapNg(): Packet[] {
    const packets: Packet[] = [];
    let offset = 0;
    let packetIndex = 1;
    let baseTime: number | null = null;

    while (offset + 8 <= this.bytes.length) {
      const blockType = this.view.getUint32(offset, true);
      const blockTotalLength = this.view.getUint32(offset + 4, true);

      if (blockTotalLength < 12 || offset + blockTotalLength > this.bytes.length) {
        break;
      }

      // Enhanced Packet Block (EPB)
      if (blockType === 0x00000006) {
        if (offset + 28 <= this.bytes.length) {
          const tsHigh = this.view.getUint32(offset + 12, true);
          const tsLow = this.view.getUint32(offset + 16, true);
          const capLen = this.view.getUint32(offset + 20, true);
          const origLen = this.view.getUint32(offset + 24, true);

          const rawTs = (BigInt(tsHigh) << 32n) | BigInt(tsLow);
          // Default pcapng resolution is 1 microsecond (1e6)
          const timestamp = Number(rawTs) / 1e6;
          if (baseTime === null) baseTime = timestamp;
          const relativeTime = Math.max(0, timestamp - baseTime);

          const packetOffset = offset + 28;
          if (packetOffset + capLen <= offset + blockTotalLength) {
            const packetData = this.bytes.slice(packetOffset, packetOffset + capLen);
            const decoded = this.decodePacketData(packetIndex, timestamp, relativeTime, packetData, origLen, 1);
            packets.push(decoded);
            packetIndex++;
          }
        }
      }

      offset += blockTotalLength;
    }

    return packets;
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
    packet.destMac = this.formatMac(data.slice(0, 6));
    packet.sourceMac = this.formatMac(data.slice(6, 12));
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

      packet.sourceIp = `${data[ipHeaderStart + 12]}.${data[ipHeaderStart + 13]}.${data[ipHeaderStart + 14]}.${data[ipHeaderStart + 15]}`;
      packet.destIp = `${data[ipHeaderStart + 16]}.${data[ipHeaderStart + 17]}.${data[ipHeaderStart + 18]}.${data[ipHeaderStart + 19]}`;

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
        const flagsByte = data[transportOffset + 13];
        packet.tcpFlags = {
          urg: (flagsByte & 0x20) !== 0,
          ack: (flagsByte & 0x10) !== 0,
          psh: (flagsByte & 0x08) !== 0,
          rst: (flagsByte & 0x04) !== 0,
          syn: (flagsByte & 0x02) !== 0,
          fin: (flagsByte & 0x01) !== 0,
        };

        const payloadStart = transportOffset + dataOffset;
        if (payloadStart <= data.length) {
          const payload = data.slice(payloadStart);
          packet.payloadLength = payload.length;
          packet.payloadBytes = payload;
          packet.payloadText = this.bytesToAscii(payload);
          this.decodeApplicationLayer(packet);
        }

        if (packet.info === 'Raw Frame') {
          const flagsStr = [
            packet.tcpFlags.syn ? 'SYN' : '',
            packet.tcpFlags.ack ? 'ACK' : '',
            packet.tcpFlags.fin ? 'FIN' : '',
            packet.tcpFlags.rst ? 'RST' : '',
            packet.tcpFlags.psh ? 'PSH' : '',
          ].filter(Boolean).join(', ');
          packet.info = `${packet.sourcePort} → ${packet.destPort} [${flagsStr || 'TCP'}] Seq=${packet.seqNumber} Ack=${packet.ackNumber} Len=${packet.payloadLength}`;
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
          const payload = data.slice(payloadStart, Math.min(data.length, payloadStart + (udpLen - 8)));
          packet.payloadLength = payload.length;
          packet.payloadBytes = payload;
          packet.payloadText = this.bytesToAscii(payload);
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
        packet.info = `${icmpDesc} id=0x${((data[transportOffset+4]<<8)|data[transportOffset+5]).toString(16)} code=${code}`;
      }
    } 
    // ARP
    else if (etherType === 0x0806 && data.length >= ethOffset + 28) {
      packet.protocol = 'ARP';
      packet.transportProtocol = 'ARP';
      const opcode = (data[ethOffset + 6] << 8) | data[ethOffset + 7];
      const senderIp = `${data[ethOffset+14]}.${data[ethOffset+15]}.${data[ethOffset+16]}.${data[ethOffset+17]}`;
      const targetIp = `${data[ethOffset+24]}.${data[ethOffset+25]}.${data[ethOffset+26]}.${data[ethOffset+27]}`;
      packet.sourceIp = senderIp;
      packet.destIp = targetIp;
      packet.info = opcode === 1 ? `Who has ${targetIp}? Tell ${senderIp}` : `${senderIp} is at ${this.formatMac(data.slice(ethOffset + 8, ethOffset + 14))}`;
    }

    return packet;
  }

  private decodeApplicationLayer(packet: Packet): void {
    const payload = packet.payloadBytes;
    if (!payload || payload.length === 0) return;

    const srcPort = packet.sourcePort || 0;
    const dstPort = packet.destPort || 0;
    const text = packet.payloadText || '';

    // DNS (Port 53)
    if (srcPort === 53 || dstPort === 53) {
      this.decodeDns(packet);
      return;
    }

    // HTTP (Port 80, 8080, 8000, 3000, or HTTP text signature)
    if (
      srcPort === 80 || dstPort === 80 ||
      srcPort === 8080 || dstPort === 8080 ||
      srcPort === 3000 || dstPort === 3000 ||
      text.startsWith('GET ') || text.startsWith('POST ') || text.startsWith('PUT ') || 
      text.startsWith('DELETE ') || text.startsWith('HEAD ') || text.startsWith('OPTIONS ') ||
      text.startsWith('HTTP/1.0') || text.startsWith('HTTP/1.1') || text.startsWith('HTTP/2')
    ) {
      if (this.decodeHttp(packet)) {
        return;
      }
    }

    // FTP (Port 21)
    if (srcPort === 21 || dstPort === 21) {
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
      this.decodeSmtp(packet);
      return;
    }

    // TLS / HTTPS (Port 443)
    if (srcPort === 443 || dstPort === 443 || (payload[0] === 0x16 && payload[1] === 0x03)) {
      this.decodeTls(packet);
      return;
    }
  }

  private decodeHttp(packet: Packet): boolean {
    const text = packet.payloadText || '';
    const lines = text.split('\r\n');
    if (lines.length === 0) return false;

    const firstLine = lines[0];
    const isRequest = /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+([^\s]+)\s+HTTP\/1\.[01]/.test(firstLine);
    const isResponse = /^HTTP\/1\.[01]\s+(\d{3})\s*(.*)/.test(firstLine);

    if (!isRequest && !isResponse) {
      return false;
    }

    packet.protocol = 'HTTP';
    packet.isCleartext = true;

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
    const anCount = (payload[6] << 8) | payload[7];

    const queries: { name: string; type: string }[] = [];
    const answers: { name: string; type: string; data: string }[] = [];

    let offset = 12;
    for (let i = 0; i < qdCount && offset < payload.length; i++) {
      const nameResult = this.parseDnsName(payload, offset);
      offset = nameResult.nextOffset;
      if (offset + 4 <= payload.length) {
        const qType = (payload[offset] << 8) | payload[offset + 1];
        offset += 4; // qtype + qclass
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

      // Pointer (compressed name)
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
      // Command
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
      // Response
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
    
    // Strip IAC (0xFF) Telnet negotiation commands
    let cleanText = '';
    for (let i = 0; i < raw.length; i++) {
      if (raw[i] === 0xff) {
        i += 2; // skip command and option
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

    // TLS Record Header: [ContentType (1), Version (2), Length (2)]
    const contentType = payload[0];
    if (contentType === 0x16) { // Handshake
      const handshakeType = payload[5];
      if (handshakeType === 1) { // Client Hello
        const sni = this.extractTlsSni(payload);
        packet.tlsDetails = {
          handshakeType: 'Client Hello',
          sni: sni || undefined,
        };
        packet.info = `TLS Client Hello ${sni ? `[SNI: ${sni}]` : ''}`;
        return;
      } else if (handshakeType === 2) { // Server Hello
        packet.tlsDetails = { handshakeType: 'Server Hello' };
        packet.info = 'TLS Server Hello';
        return;
      }
    }
    packet.info = 'TLS Encrypted Application Data';
  }

  private extractTlsSni(payload: Uint8Array): string | null {
    try {
      // Find extensions offset in Client Hello
      // 0: Record (5 bytes)
      // 5: Handshake Header (4 bytes)
      // 9: Client Version (2 bytes)
      // 11: Random (32 bytes) -> 43
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

        if (extType === 0) { // server_name extension
          if (offset + 5 <= payload.length) {
            // list length (2), type (1), name length (2)
            const nameLen = (payload[offset + 3] << 8) | payload[offset + 4];
            let name = '';
            for (let i = 0; i < nameLen; i++) {
              name += String.fromCharCode(payload[offset + 5 + i]);
            }
            return name;
          }
        }
        offset += extLen;
      }
    } catch {
      // Ignore parse failure
    }
    return null;
  }

  private formatMac(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join(':');
  }

  private bytesToAscii(bytes: Uint8Array): string {
    let str = '';
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      if (b >= 32 && b <= 126) {
        str += String.fromCharCode(b);
      } else if (b === 10 || b === 13 || b === 9) {
        str += String.fromCharCode(b);
      } else {
        str += '.';
      }
    }
    return str;
  }
}
