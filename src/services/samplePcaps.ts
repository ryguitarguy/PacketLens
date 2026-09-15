/**
 * Utility to generate valid binary PCAP files in-memory for testing,
 * demonstration, and immediate forensic analysis.
 */

interface RawPacketDef {
  timeSec: number;
  timeUsec: number;
  srcMac: string;
  dstMac: string;
  srcIp: string;
  dstIp: string;
  proto: 'TCP' | 'UDP';
  srcPort: number;
  dstPort: number;
  tcpFlags?: { syn?: boolean; ack?: boolean; psh?: boolean; fin?: boolean; rst?: boolean };
  seq?: number;
  ack?: number;
  payloadStr?: string;
  dnsQuery?: { name: string; type: number };
}

export class PcapBuilder {
  private packets: Uint8Array[] = [];
  private packetHeaders: { sec: number; usec: number; len: number }[] = [];

  public addPacket(def: RawPacketDef) {
    const ethHeader = this.createEthHeader(def.dstMac, def.srcMac, 0x0800);
    let l4Header: Uint8Array;
    let payloadBytes: Uint8Array;

    if (def.dnsQuery) {
      payloadBytes = this.createDnsQueryPayload(def.dnsQuery.name, def.dnsQuery.type);
    } else {
      payloadBytes = def.payloadStr ? new TextEncoder().encode(def.payloadStr) : new Uint8Array(0);
    }

    if (def.proto === 'TCP') {
      l4Header = this.createTcpHeader(
        def.srcPort,
        def.dstPort,
        def.seq || 1000,
        def.ack || 0,
        def.tcpFlags || {},
        payloadBytes.length
      );
    } else {
      l4Header = this.createUdpHeader(def.srcPort, def.dstPort, payloadBytes.length);
    }

    const ipTotalLen = 20 + l4Header.length + payloadBytes.length;
    const ipHeader = this.createIpv4Header(
      def.srcIp,
      def.dstIp,
      def.proto === 'TCP' ? 6 : 17,
      ipTotalLen
    );

    const fullFrame = new Uint8Array(ethHeader.length + ipHeader.length + l4Header.length + payloadBytes.length);
    let offset = 0;
    fullFrame.set(ethHeader, offset); offset += ethHeader.length;
    fullFrame.set(ipHeader, offset); offset += ipHeader.length;
    fullFrame.set(l4Header, offset); offset += l4Header.length;
    fullFrame.set(payloadBytes, offset);

    this.packets.push(fullFrame);
    this.packetHeaders.push({
      sec: def.timeSec,
      usec: def.timeUsec,
      len: fullFrame.length,
    });
  }

  public toArrayBuffer(): ArrayBuffer {
    // 24 bytes global header + 16 bytes per packet header + packet data
    let totalSize = 24;
    for (let i = 0; i < this.packets.length; i++) {
      totalSize += 16 + this.packets[i].length;
    }

    const buffer = new ArrayBuffer(totalSize);
    const view = new DataView(buffer);
    const uint8 = new Uint8Array(buffer);

    // Global Header (Little Endian standard pcap: 0xd4c3b2a1)
    view.setUint32(0, 0xd4c3b2a1, true); // Magic
    view.setUint16(4, 2, true);          // Version major
    view.setUint16(6, 4, true);          // Version minor
    view.setInt32(8, 0, true);           // Thiszone
    view.setUint32(12, 0, true);         // Sigfigs
    view.setUint32(16, 65535, true);     // Snaplen
    view.setUint32(20, 1, true);         // Network: 1 = Ethernet

    let offset = 24;
    for (let i = 0; i < this.packets.length; i++) {
      const ph = this.packetHeaders[i];
      const pData = this.packets[i];

      view.setUint32(offset, ph.sec, true);
      view.setUint32(offset + 4, ph.usec, true);
      view.setUint32(offset + 8, ph.len, true); // Captured length
      view.setUint32(offset + 12, ph.len, true); // Original wire length
      offset += 16;

      uint8.set(pData, offset);
      offset += pData.length;
    }

    return buffer;
  }

  private createEthHeader(dstMac: string, srcMac: string, etherType: number): Uint8Array {
    const h = new Uint8Array(14);
    const parseMac = (mac: string) => mac.split(':').map(x => parseInt(x, 16));
    const dBytes = parseMac(dstMac);
    const sBytes = parseMac(srcMac);
    for (let i = 0; i < 6; i++) h[i] = dBytes[i] || 0;
    for (let i = 0; i < 6; i++) h[6 + i] = sBytes[i] || 0;
    h[12] = (etherType >> 8) & 0xff;
    h[13] = etherType & 0xff;
    return h;
  }

  private createIpv4Header(srcIp: string, dstIp: string, protocol: number, totalLen: number): Uint8Array {
    const h = new Uint8Array(20);
    h[0] = 0x45; // Version 4, IHL 5 (20 bytes)
    h[1] = 0x00; // DSCP / ECN
    h[2] = (totalLen >> 8) & 0xff;
    h[3] = totalLen & 0xff;
    h[4] = 0x1c; h[5] = 0x7b; // Identification
    h[6] = 0x40; h[7] = 0x00; // Flags (Don't Fragment)
    h[8] = 64;   // TTL
    h[9] = protocol;
    h[10] = 0x00; h[11] = 0x00; // Checksum placeholder

    const s = srcIp.split('.').map(Number);
    const d = dstIp.split('.').map(Number);
    for (let i = 0; i < 4; i++) h[12 + i] = s[i] || 0;
    for (let i = 0; i < 4; i++) h[16 + i] = d[i] || 0;

    return h;
  }

  private createTcpHeader(
    srcPort: number,
    dstPort: number,
    seq: number,
    ack: number,
    flags: { syn?: boolean; ack?: boolean; psh?: boolean; fin?: boolean; rst?: boolean },
    _payloadLen: number
  ): Uint8Array {
    const h = new Uint8Array(20);
    h[0] = (srcPort >> 8) & 0xff;
    h[1] = srcPort & 0xff;
    h[2] = (dstPort >> 8) & 0xff;
    h[3] = dstPort & 0xff;

    // Sequence number
    h[4] = (seq >> 24) & 0xff;
    h[5] = (seq >> 16) & 0xff;
    h[6] = (seq >> 8) & 0xff;
    h[7] = seq & 0xff;

    // Ack number
    h[8] = (ack >> 24) & 0xff;
    h[9] = (ack >> 16) & 0xff;
    h[10] = (ack >> 8) & 0xff;
    h[11] = ack & 0xff;

    h[12] = 0x50; // Data offset 5 (20 bytes)
    let f = 0;
    if (flags.fin) f |= 0x01;
    if (flags.syn) f |= 0x02;
    if (flags.rst) f |= 0x04;
    if (flags.psh) f |= 0x08;
    if (flags.ack) f |= 0x10;
    h[13] = f;

    // Window size 64240
    h[14] = 0xfa;
    h[15] = 0xf0;

    return h;
  }

  private createUdpHeader(srcPort: number, dstPort: number, payloadLen: number): Uint8Array {
    const h = new Uint8Array(8);
    h[0] = (srcPort >> 8) & 0xff;
    h[1] = srcPort & 0xff;
    h[2] = (dstPort >> 8) & 0xff;
    h[3] = dstPort & 0xff;
    const len = 8 + payloadLen;
    h[4] = (len >> 8) & 0xff;
    h[5] = len & 0xff;
    h[6] = 0x00; h[7] = 0x00; // Checksum
    return h;
  }

  private createDnsQueryPayload(domain: string, qtype: number = 1): Uint8Array {
    const labels = domain.split('.');
    let nameLen = 1; // ending 0
    for (const l of labels) nameLen += 1 + l.length;

    const payload = new Uint8Array(12 + nameLen + 4);
    // Header
    payload[0] = 0x4a; payload[1] = 0x8b; // ID
    payload[2] = 0x01; payload[3] = 0x00; // Standard query with recursion desired
    payload[4] = 0x00; payload[5] = 0x01; // QDCOUNT: 1
    payload[6] = 0x00; payload[7] = 0x00; // ANCOUNT: 0

    let offset = 12;
    for (const l of labels) {
      payload[offset++] = l.length;
      for (let i = 0; i < l.length; i++) {
        payload[offset++] = l.charCodeAt(i);
      }
    }
    payload[offset++] = 0; // End of name

    // QTYPE
    payload[offset++] = (qtype >> 8) & 0xff;
    payload[offset++] = qtype & 0xff;
    // QCLASS (IN = 1)
    payload[offset++] = 0x00;
    payload[offset++] = 0x01;

    return payload;
  }
}

export interface SamplePcapInfo {
  id: string;
  name: string;
  badge: string;
  description: string;
  highlights: string[];
  generate: () => ArrayBuffer;
}

export const SAMPLE_PCAPS: SamplePcapInfo[] = [
  {
    id: 'credential_leak_audit',
    name: 'Cleartext Credentials & Insecure Protocols',
    badge: 'Critical Vulnerabilities',
    description: 'A rich forensic capture containing HTTP login POST with passwords, HTTP Basic Auth, Telnet administration, FTP credentials, unencrypted cookies, and leaked API secrets.',
    highlights: ['HTTP Login Password Leak', 'Decoded Basic Auth', 'Telnet Root Shell', 'FTP Plaintext USER/PASS', 'Internal DNS Leaks'],
    generate: () => {
      const b = new PcapBuilder();
      const baseSec = 1773738000;
      const clientMac = '00:0c:29:4f:8e:12';
      const srvMac = '00:50:56:c0:00:08';
      const clientIp = '192.168.1.105';
      const webServerIp = '192.168.1.50';
      const ftpServerIp = '192.168.1.75';
      const routerIp = '192.168.1.1';
      const dnsServerIp = '192.168.1.2';

      // 1. DNS queries for internal and external services
      b.addPacket({
        timeSec: baseSec, timeUsec: 100000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: dnsServerIp,
        proto: 'UDP', srcPort: 54120, dstPort: 53,
        dnsQuery: { name: 'intranet-login.corp.local', type: 1 }
      });

      b.addPacket({
        timeSec: baseSec, timeUsec: 250000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: dnsServerIp,
        proto: 'UDP', srcPort: 54121, dstPort: 53,
        dnsQuery: { name: 'db-master.internal.finance', type: 1 }
      });

      // 2. HTTP POST with Plaintext Form Credentials (username & password)
      b.addPacket({
        timeSec: baseSec + 1, timeUsec: 150000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: webServerIp,
        proto: 'TCP', srcPort: 49152, dstPort: 80,
        tcpFlags: { syn: true }, seq: 1000, ack: 0
      });

      b.addPacket({
        timeSec: baseSec + 1, timeUsec: 152000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: webServerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 80, dstPort: 49152,
        tcpFlags: { syn: true, ack: true }, seq: 5000, ack: 1001
      });

      const httpPostPayload = 
        `POST /api/v1/auth/login HTTP/1.1\r\n` +
        `Host: intranet-login.corp.local\r\n` +
        `User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n` +
        `Content-Type: application/x-www-form-urlencoded\r\n` +
        `Content-Length: 58\r\n` +
        `Cookie: session_id=sess_9f8e7d6c5b4a; tracking_id=trk_8820\r\n` +
        `\r\n` +
        `username=sysadmin_clark&password=SuperSecretEnterprise2026!`;

      b.addPacket({
        timeSec: baseSec + 1, timeUsec: 200000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: webServerIp,
        proto: 'TCP', srcPort: 49152, dstPort: 80,
        tcpFlags: { psh: true, ack: true }, seq: 1001, ack: 5001,
        payloadStr: httpPostPayload
      });

      const httpResponsePayload = 
        `HTTP/1.1 200 OK\r\n` +
        `Content-Type: application/json\r\n` +
        `Set-Cookie: auth_jwt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.fake_token_leak; Path=/\r\n` +
        `\r\n` +
        `{"status":"success","user":"sysadmin_clark","role":"SuperAdmin","aws_access_key":"AKIAIOSFODNN7EXAMPLE"}`;

      b.addPacket({
        timeSec: baseSec + 1, timeUsec: 350000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: webServerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 80, dstPort: 49152,
        tcpFlags: { psh: true, ack: true }, seq: 5001, ack: 1001 + httpPostPayload.length,
        payloadStr: httpResponsePayload
      });

      // 3. HTTP GET with Basic Auth (admin:CompanyVault2026#)
      const b64Auth = btoa('admin:CompanyVault2026#');
      const httpBasicAuthPayload =
        `GET /admin/vault/export HTTP/1.1\r\n` +
        `Host: intranet-login.corp.local\r\n` +
        `Authorization: Basic ${b64Auth}\r\n` +
        `Accept: application/json\r\n\r\n`;

      b.addPacket({
        timeSec: baseSec + 2, timeUsec: 100000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: webServerIp,
        proto: 'TCP', srcPort: 49154, dstPort: 80,
        tcpFlags: { psh: true, ack: true }, seq: 2001, ack: 6001,
        payloadStr: httpBasicAuthPayload
      });

      // 4. FTP Plaintext Authentication Session (Port 21)
      b.addPacket({
        timeSec: baseSec + 3, timeUsec: 100000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: ftpServerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 21, dstPort: 49160,
        tcpFlags: { psh: true, ack: true }, seq: 7001, ack: 3001,
        payloadStr: `220 Microsoft FTP Service Ready\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 3, timeUsec: 250000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: ftpServerIp,
        proto: 'TCP', srcPort: 49160, dstPort: 21,
        tcpFlags: { psh: true, ack: true }, seq: 3001, ack: 7035,
        payloadStr: `USER backup_svc_user\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 3, timeUsec: 320000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: ftpServerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 21, dstPort: 49160,
        tcpFlags: { psh: true, ack: true }, seq: 7035, ack: 3022,
        payloadStr: `331 Password required for backup_svc_user\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 3, timeUsec: 450000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: ftpServerIp,
        proto: 'TCP', srcPort: 49160, dstPort: 21,
        tcpFlags: { psh: true, ack: true }, seq: 3022, ack: 7080,
        payloadStr: `PASS FtpBackupVault!9942\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 3, timeUsec: 600000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: ftpServerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 21, dstPort: 49160,
        tcpFlags: { psh: true, ack: true }, seq: 7080, ack: 3048,
        payloadStr: `230 User logged in successfully.\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 3, timeUsec: 750000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: ftpServerIp,
        proto: 'TCP', srcPort: 49160, dstPort: 21,
        tcpFlags: { psh: true, ack: true }, seq: 3048, ack: 7115,
        payloadStr: `RETR confidential_q3_financials.xlsx\r\n`
      });

      // 5. Telnet Unencrypted Management Session (Port 23)
      b.addPacket({
        timeSec: baseSec + 4, timeUsec: 100000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: routerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 23, dstPort: 49170,
        tcpFlags: { psh: true, ack: true }, seq: 8001, ack: 4001,
        payloadStr: `Core-Gateway-Router> User Access Verification\r\nUsername: `
      });

      b.addPacket({
        timeSec: baseSec + 4, timeUsec: 250000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: routerIp,
        proto: 'TCP', srcPort: 49170, dstPort: 23,
        tcpFlags: { psh: true, ack: true }, seq: 4001, ack: 8060,
        payloadStr: `netadmin\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 4, timeUsec: 350000,
        srcMac: srvMac, dstMac: clientMac,
        srcIp: routerIp, dstIp: clientIp,
        proto: 'TCP', srcPort: 23, dstPort: 49170,
        tcpFlags: { psh: true, ack: true }, seq: 8060, ack: 4011,
        payloadStr: `Password: `
      });

      b.addPacket({
        timeSec: baseSec + 4, timeUsec: 500000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: routerIp,
        proto: 'TCP', srcPort: 49170, dstPort: 23,
        tcpFlags: { psh: true, ack: true }, seq: 4011, ack: 8072,
        payloadStr: `CiscoEn@ble9922!\r\n`
      });

      b.addPacket({
        timeSec: baseSec + 4, timeUsec: 650000,
        srcMac: clientMac, dstMac: srvMac,
        srcIp: clientIp, dstIp: routerIp,
        proto: 'TCP', srcPort: 49170, dstPort: 23,
        tcpFlags: { psh: true, ack: true }, seq: 4028, ack: 8090,
        payloadStr: `enable\r\nshow running-config\r\n`
      });

      return b.toArrayBuffer();
    }
  },
  {
    id: 'port_scan_recon',
    name: 'Port Scan & Reconnaissance Anomaly',
    badge: 'Reconnaissance Probe',
    description: 'Reconnaissance attack capture where an external scanner performs rapid SYN scanning across multiple critical ports searching for vulnerable services.',
    highlights: ['SYN Stealth Scan', '16 Ports Targeted', 'T1046 Network Discovery', 'RST Flag Responses', 'Service Fingerprinting'],
    generate: () => {
      const b = new PcapBuilder();
      const baseSec = 1773738100;
      const scannerMac = '00:11:22:33:44:55';
      const targetMac = '00:50:56:c0:00:08';
      const scannerIp = '10.0.4.150';
      const targetIp = '192.168.1.50';

      const scanPorts = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 4444, 8080];

      scanPorts.forEach((port, idx) => {
        const uSec = idx * 50000;
        // SYN probe
        b.addPacket({
          timeSec: baseSec + Math.floor(idx / 8), timeUsec: uSec % 1000000,
          srcMac: scannerMac, dstMac: targetMac,
          srcIp: scannerIp, dstIp: targetIp,
          proto: 'TCP', srcPort: 52000 + idx, dstPort: port,
          tcpFlags: { syn: true }, seq: 10000 + idx, ack: 0
        });

        // Response: Open on 80 & 443 & 22 (SYN+ACK), Closed on others (RST+ACK)
        const isOpen = port === 80 || port === 443 || port === 22;
        b.addPacket({
          timeSec: baseSec + Math.floor(idx / 8), timeUsec: (uSec + 15000) % 1000000,
          srcMac: targetMac, dstMac: scannerMac,
          srcIp: targetIp, dstIp: scannerIp,
          proto: 'TCP', srcPort: port, dstPort: 52000 + idx,
          tcpFlags: isOpen ? { syn: true, ack: true } : { rst: true, ack: true },
          seq: 30000 + idx, ack: 10001 + idx
        });

        // If open, scanner sends RST to tear down (Stealth SYN scan)
        if (isOpen) {
          b.addPacket({
            timeSec: baseSec + Math.floor(idx / 8), timeUsec: (uSec + 25000) % 1000000,
            srcMac: scannerMac, dstMac: targetMac,
            srcIp: scannerIp, dstIp: targetIp,
            proto: 'TCP', srcPort: 52000 + idx, dstPort: port,
            tcpFlags: { rst: true }, seq: 10001 + idx, ack: 0
          });
        }
      });

      return b.toArrayBuffer();
    }
  },
  {
    id: 'dns_exfiltration_tunnel',
    name: 'DNS Tunneling & Data Exfiltration',
    badge: 'Covert Channel',
    description: 'Attack capture showing an insider or malware exfiltrating encrypted proprietary database records hidden inside high-entropy DNS query subdomains.',
    highlights: ['Covert Exfiltration over UDP 53', 'High Shannon Entropy (>4.2)', 'T1048 Exfiltration', 'Base32 Payload Chunks', 'C2 Tunnel'],
    generate: () => {
      const b = new PcapBuilder();
      const baseSec = 1773738200;
      const clientMac = '00:0c:29:ab:cd:ef';
      const gwMac = '00:50:56:00:11:22';
      const clientIp = '192.168.1.188';
      const rogueDns = '198.51.100.53';

      const exfilChunks = [
        'MZXW6YTBOJRWG2LOM4XW43TBNZ2Q.tunnel.exfil-c2.net',
        'OJQW4ZZON5SGC3THNFXGO3TJNJXW.tunnel.exfil-c2.net',
        'G5SGC43FNRXW2LLPOVZXI3TPOJXX.tunnel.exfil-c2.net',
        '43VON52GC3TEORZGS3THNVRW63T2.tunnel.exfil-c2.net',
        '7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e.tunnel.exfil-c2.net',
        '9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c.tunnel.exfil-c2.net',
      ];

      exfilChunks.forEach((domain, idx) => {
        b.addPacket({
          timeSec: baseSec + idx, timeUsec: 120000,
          srcMac: clientMac, dstMac: gwMac,
          srcIp: clientIp, dstIp: rogueDns,
          proto: 'UDP', srcPort: 48000 + idx, dstPort: 53,
          dnsQuery: { name: domain, type: 16 } // TXT query
        });

        b.addPacket({
          timeSec: baseSec + idx, timeUsec: 180000,
          srcMac: gwMac, dstMac: clientMac,
          srcIp: rogueDns, dstIp: clientIp,
          proto: 'UDP', srcPort: 53, dstPort: 48000 + idx,
          dnsQuery: { name: domain, type: 16 }
        });
      });

      return b.toArrayBuffer();
    }
  },
  {
    id: 'mixed_enterprise_traffic',
    name: 'Enterprise Traffic & API Bearer Leak',
    badge: 'Enterprise Baseline',
    description: 'Realistic mix of encrypted TLS traffic (with SNI inspection), unencrypted internal REST APIs exposing JWT Bearer tokens, DNS inquiries, and HTTP communications.',
    highlights: ['TLS Handshake & SNI Extraction', 'API Bearer Token Exposed', 'REST JSON Body', 'Multi-Protocol Timeline'],
    generate: () => {
      const b = new PcapBuilder();
      const baseSec = 1773738300;
      const clientMac = '00:0c:29:44:55:66';
      const routerMac = '00:50:56:ee:ff:aa';
      const clientIp = '10.10.20.45';
      const apiServer = '10.10.20.100';
      const cloudflareIp = '104.16.132.229';

      // 1. Unencrypted API Call with Bearer Token
      const apiRequest = 
        `GET /api/v2/customer/pii?limit=100 HTTP/1.1\r\n` +
        `Host: internal-crm.enterprise.com\r\n` +
        `Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImVtYWlsIjoiYWRtaW5AZW50ZXJwcmlzZS5jb20ifQ.sample_signature_leak\r\n` +
        `Accept: application/json\r\n\r\n`;

      b.addPacket({
        timeSec: baseSec, timeUsec: 100000,
        srcMac: clientMac, dstMac: routerMac,
        srcIp: clientIp, dstIp: apiServer,
        proto: 'TCP', srcPort: 51230, dstPort: 8080,
        tcpFlags: { psh: true, ack: true }, seq: 1000, ack: 2000,
        payloadStr: apiRequest
      });

      // Response with PII emails
      const apiResponse =
        `HTTP/1.1 200 OK\r\n` +
        `Content-Type: application/json\r\n\r\n` +
        `{"records":[{"id":101,"name":"Sarah Connor","email":"sarah.connor@cyberdyne.org","ssn":"***-**-4921"},{"id":102,"name":"Miles Dyson","email":"dyson@cyberdyne.org"}]}`;

      b.addPacket({
        timeSec: baseSec, timeUsec: 250000,
        srcMac: routerMac, dstMac: clientMac,
        srcIp: apiServer, dstIp: clientIp,
        proto: 'TCP', srcPort: 8080, dstPort: 51230,
        tcpFlags: { psh: true, ack: true }, seq: 2000, ack: 1000 + apiRequest.length,
        payloadStr: apiResponse
      });

      // 2. DNS query
      b.addPacket({
        timeSec: baseSec + 1, timeUsec: 100000,
        srcMac: clientMac, dstMac: routerMac,
        srcIp: clientIp, dstIp: '1.1.1.1',
        proto: 'UDP', srcPort: 53112, dstPort: 53,
        dnsQuery: { name: 'api.github.com', type: 1 }
      });

      // 3. TLS Client Hello (Encrypted traffic)
      b.addPacket({
        timeSec: baseSec + 1, timeUsec: 400000,
        srcMac: clientMac, dstMac: routerMac,
        srcIp: clientIp, dstIp: cloudflareIp,
        proto: 'TCP', srcPort: 54100, dstPort: 443,
        tcpFlags: { psh: true, ack: true }, seq: 5000, ack: 7000,
        payloadStr: '\x16\x03\x01\x00\x64\x01\x00\x00\x60\x03\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x13\x01\x01\x00\x00\x18\x00\x00\x00\x14\x00\x12\x00\x00\x0f\x61\x70\x69\x2e\x67\x69\x74\x68\x75\x62\x2e\x63\x6f\x6d'
      });

      return b.toArrayBuffer();
    }
  }
];
