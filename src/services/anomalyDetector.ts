import { Packet, SecurityAnomaly, CleartextItem } from '../types';

export class AnomalyDetector {
  public static detect(packets: Packet[], cleartextItems: CleartextItem[]): SecurityAnomaly[] {
    return this.detectInternal(packets, cleartextItems);
  }

  public static async detectAsync(
    packets: Packet[],
    cleartextItems: CleartextItem[],
    onProgress?: (p: { percent: number }) => void,
    shouldAbort?: () => boolean
  ): Promise<SecurityAnomaly[]> {
    return this.detectInternalAsync(packets, cleartextItems, onProgress, shouldAbort);
  }

  private static async detectInternalAsync(
    packets: Packet[],
    cleartextItems: CleartextItem[],
    onProgress?: (p: { percent: number }) => void,
    shouldAbort?: () => boolean
  ): Promise<SecurityAnomaly[]> {
    const anomalies: SecurityAnomaly[] = [];
    let anomalyIdCounter = 1;

    const addAnomaly = (anomaly: Omit<SecurityAnomaly, 'id'>) => {
      anomalies.push({
        id: `anomaly-${anomalyIdCounter++}`,
        ...anomaly,
      });
    };

    // 1. Plaintext Credentials & Sensitive Tokens Anomaly
    const credItems = cleartextItems.filter(i => i.category === 'Credentials & Passwords' || i.category === 'Session & Auth Tokens');
    if (credItems.length > 0) {
      const topOffenders = Array.from(new Set(credItems.map(c => `${c.sourceIp} → ${c.destIp} (${c.protocol})`))).slice(0, 3);
      const packetIds = Array.from(new Set(credItems.map(c => c.packetId))).slice(0, 50);
      
      addAnomaly({
        title: 'Plaintext Authentication Credentials & Tokens Transmitted',
        severity: 'critical',
        category: 'Cleartext Transmission',
        protocol: credItems[0].protocol,
        sourceIp: credItems[0].sourceIp,
        destinationIp: credItems[0].destIp,
        description: `Detected ${credItems.length} instance(s) of unencrypted passwords, HTTP Basic Auth credentials, or bearer tokens transmitted across the wire without TLS encryption. Any network eavesdropper or intermediate proxy can harvest these secrets in real-time.`,
        mitreId: 'T1552.001',
        mitreTitle: 'Credentials in Files or Unencrypted Protocols',
        packetIds,
        evidence: {
          totalCleartextSecrets: credItems.length,
          observedStreams: topOffenders,
          sampleTypes: Array.from(new Set(credItems.map(c => c.label))).slice(0, 10),
        },
      });
    }

    // 2-6. Single-pass over packets to avoid multiple heavy filter passes and keep memory light
    const synScanTracker: Map<string, { targetIp: string; ports: Set<number>; packetIds: number[]; synOnlyCount: number }> = new Map();
    const suspiciousDnsQueries: { packetId: number; name: string; entropy: number; len: number; srcIp: string; dstIp: string }[] = [];
    const entropyCache = new Map<string, number>();

    let telnetCount = 0;
    const telnetIds: number[] = [];
    let telnetSrc = '';
    let telnetDst = '';

    let ftpCount = 0;
    const ftpIds: number[] = [];
    let ftpSrc = '';
    let ftpDst = '';

    const suspiciousPorts = [4444, 1337, 6667, 31337, 8888, 9999];
    const suspiciousPortPackets: { port: number; packet: Packet }[] = [];

    const totalCount = packets.length;
    let lastYieldTime = performance.now();

    for (let i = 0; i < totalCount; i++) {
      if (shouldAbort && shouldAbort()) {
        throw new Error('Analysis cancelled by user');
      }

      const now = performance.now();
      if (now - lastYieldTime > 20 || i % 5000 === 0) {
        onProgress?.({ percent: Math.round((i / totalCount) * 100) });
        await new Promise<void>(resolve => setTimeout(resolve, 0));
        lastYieldTime = performance.now();
      }

      const packet = packets[i];

      // A. TCP SYN scan detection
      if (packet.protocol === 'TCP' && packet.tcpFlags?.syn && !packet.tcpFlags?.ack) {
        const key = `${packet.sourceIp}->${packet.destIp}`;
        let tracker = synScanTracker.get(key);
        if (!tracker && synScanTracker.size < 1000) {
          tracker = { targetIp: packet.destIp, ports: new Set(), packetIds: [], synOnlyCount: 0 };
          synScanTracker.set(key, tracker);
        }
        if (tracker) {
          if (packet.destPort && tracker.ports.size < 100) tracker.ports.add(packet.destPort);
          if (tracker.packetIds.length < 50) tracker.packetIds.push(packet.id);
          tracker.synOnlyCount++;
        }
      }

      // B. Telnet detection
      if (packet.protocol === 'TELNET') {
        telnetCount++;
        if (telnetIds.length < 50) telnetIds.push(packet.id);
        if (!telnetSrc) {
          telnetSrc = packet.sourceIp;
          telnetDst = packet.destIp;
        }
      }

      // C. FTP detection
      if (packet.protocol === 'FTP') {
        ftpCount++;
        if (ftpIds.length < 50) ftpIds.push(packet.id);
        if (!ftpSrc) {
          ftpSrc = packet.sourceIp;
          ftpDst = packet.destIp;
        }
      }

      // D. Suspicious non-standard ports
      const pPort = packet.destPort || packet.sourcePort || 0;
      if (suspiciousPorts.includes(pPort) && suspiciousPortPackets.length < 10) {
        suspiciousPortPackets.push({ port: pPort, packet });
      }

      // E. DNS Tunneling & High-Entropy
      if (packet.protocol === 'DNS' && packet.dnsDetails?.isQuery && packet.dnsDetails.queries) {
        for (const q of packet.dnsDetails.queries) {
          const parts = q.name.split('.');
          const subdomain = parts[0] || '';
          let entropy = entropyCache.get(subdomain);
          if (entropy === undefined) {
            entropy = this.calculateShannonEntropy(subdomain);
            if (entropyCache.size < 500) entropyCache.set(subdomain, entropy);
          }

          if ((subdomain.length >= 25 && entropy >= 3.4) || (q.name.length >= 45 && entropy >= 3.6)) {
            if (suspiciousDnsQueries.length < 50) {
              suspiciousDnsQueries.push({
                packetId: packet.id,
                name: q.name,
                entropy: Number(entropy.toFixed(2)),
                len: q.name.length,
                srcIp: packet.sourceIp,
                dstIp: packet.destIp,
              });
            }
          }
        }
      }
    }

    onProgress?.({ percent: 100 });

    // Port scan anomalies
    for (const [key, data] of synScanTracker.entries()) {
      const [srcIp, dstIp] = key.split('->');
      if (data.ports.size >= 4 || data.synOnlyCount >= 8) {
        const portList = Array.from(data.ports).sort((a, b) => a - b);
        addAnomaly({
          title: `Port Scan / Reconnaissance Probe (${data.ports.size} Ports Targeted)`,
          severity: data.ports.size > 8 ? 'critical' : 'high',
          category: 'Port Scan / Reconnaissance',
          protocol: 'TCP',
          sourceIp: srcIp,
          destinationIp: dstIp,
          description: `Host ${srcIp} performed rapid TCP SYN port probing against target ${dstIp}, attempting connection handshakes across ${data.ports.size} distinct ports. This activity matches signature network mapping tools (e.g. Nmap / Masscan) searching for open services.`,
          mitreId: 'T1046',
          mitreTitle: 'Network Service Discovery',
          packetIds: data.packetIds,
          evidence: {
            probedPortsCount: data.ports.size,
            sampleProbedPorts: portList.slice(0, 15).join(', ') + (portList.length > 15 ? '...' : ''),
            totalSynPackets: data.synOnlyCount,
          },
        });
      }
    }

    // DNS Tunneling Anomaly
    if (suspiciousDnsQueries.length >= 2) {
      const firstSus = suspiciousDnsQueries[0];
      addAnomaly({
        title: 'DNS Tunneling / Data Exfiltration Anomaly',
        severity: 'critical',
        category: 'DNS Tunneling / Exfiltration',
        protocol: 'DNS',
        sourceIp: firstSus.srcIp,
        destinationIp: firstSus.dstIp,
        description: `Identified ${suspiciousDnsQueries.length} DNS query requests with abnormally high Shannon entropy and unusually long subdomain strings. This traffic pattern strongly suggests DNS covert channel communication or data exfiltration over UDP port 53.`,
        mitreId: 'T1048.003',
        mitreTitle: 'Exfiltration Over Alternative Protocol: DNS Exfiltration',
        packetIds: suspiciousDnsQueries.map(s => s.packetId),
        evidence: {
          suspiciousQueriesCount: suspiciousDnsQueries.length,
          sampleDomain: firstSus.name,
          shannonEntropy: firstSus.entropy,
          subdomainLength: firstSus.len,
        },
      });
    }

    // Telnet Anomaly
    if (telnetCount > 0) {
      addAnomaly({
        title: 'Cleartext Management Protocol In Use: Telnet (Port 23)',
        severity: 'high',
        category: 'Insecure Legacy Protocol',
        protocol: 'TELNET',
        sourceIp: telnetSrc,
        sourcePort: 23,
        destinationIp: telnetDst,
        description: `Host ${telnetSrc} is using unencrypted Telnet protocol for remote shell administration. Telnet sends all keystrokes, administrative credentials, and server responses in plaintext without integrity protection.`,
        mitreId: 'T1040',
        mitreTitle: 'Network Sniffing / Insecure Remote Services',
        packetIds: telnetIds,
        evidence: {
          packetCount: telnetCount,
          port: 23,
          recommendation: 'Decommission Telnet immediately and enforce SSH (Port 22) with key-based authentication.',
        },
      });
    }

    // FTP Anomaly
    if (ftpCount > 0) {
      addAnomaly({
        title: 'Cleartext File Transfer Protocol In Use: FTP (Port 21)',
        severity: 'medium',
        category: 'Insecure Legacy Protocol',
        protocol: 'FTP',
        sourceIp: ftpSrc,
        sourcePort: 21,
        destinationIp: ftpDst,
        description: `Unencrypted FTP (File Transfer Protocol) detected between ${ftpSrc} and ${ftpDst}. File contents, directory structures, and authentication credentials traverse the wire in cleartext.`,
        mitreId: 'T1040',
        mitreTitle: 'Network Sniffing',
        packetIds: ftpIds,
        evidence: {
          packetCount: ftpCount,
          port: 21,
          recommendation: 'Migrate file transfer workflows to SFTP (SSH File Transfer) or FTPS (TLS).',
        },
      });
    }

    // Suspicious Ports Anomaly
    if (suspiciousPortPackets.length > 0) {
      const { port: flaggedPort, packet: p } = suspiciousPortPackets[0];
      addAnomaly({
        title: `Suspicious Non-Standard Port Traffic (Port ${flaggedPort})`,
        severity: 'high',
        category: 'Suspicious Traffic Spike',
        protocol: p.protocol,
        sourceIp: p.sourceIp,
        sourcePort: p.sourcePort,
        destinationIp: p.destIp,
        destinationPort: p.destPort,
        description: `Observed active communication over port ${flaggedPort}, which is commonly associated with reverse shell payloads, IRC botnet command-and-control, or unauthorized backdoor utilities.`,
        mitreId: 'T1571',
        mitreTitle: 'Non-Standard Port',
        packetIds: suspiciousPortPackets.map(item => item.packet.id),
        evidence: {
          flaggedPort,
          protocol: p.protocol,
          recommendation: 'Isolate host endpoint and inspect active processes listening on this port.',
        },
      });
    }

    return anomalies;
  }

  private static detectInternal(packets: Packet[], cleartextItems: CleartextItem[]): SecurityAnomaly[] {
    const anomalies: SecurityAnomaly[] = [];
    let anomalyIdCounter = 1;

    const addAnomaly = (anomaly: Omit<SecurityAnomaly, 'id'>) => {
      anomalies.push({
        id: `anomaly-${anomalyIdCounter++}`,
        ...anomaly,
      });
    };

    const credItems = cleartextItems.filter(i => i.category === 'Credentials & Passwords' || i.category === 'Session & Auth Tokens');
    if (credItems.length > 0) {
      const topOffenders = Array.from(new Set(credItems.map(c => `${c.sourceIp} → ${c.destIp} (${c.protocol})`))).slice(0, 3);
      const packetIds = Array.from(new Set(credItems.map(c => c.packetId))).slice(0, 50);
      
      addAnomaly({
        title: 'Plaintext Authentication Credentials & Tokens Transmitted',
        severity: 'critical',
        category: 'Cleartext Transmission',
        protocol: credItems[0].protocol,
        sourceIp: credItems[0].sourceIp,
        destinationIp: credItems[0].destIp,
        description: `Detected ${credItems.length} instance(s) of unencrypted passwords, HTTP Basic Auth credentials, or bearer tokens transmitted across the wire without TLS encryption. Any network eavesdropper or intermediate proxy can harvest these secrets in real-time.`,
        mitreId: 'T1552.001',
        mitreTitle: 'Credentials in Files or Unencrypted Protocols',
        packetIds,
        evidence: {
          totalCleartextSecrets: credItems.length,
          observedStreams: topOffenders,
          sampleTypes: Array.from(new Set(credItems.map(c => c.label))).slice(0, 10),
        },
      });
    }

    const synScanTracker: Map<string, { targetIp: string; ports: Set<number>; packetIds: number[]; synOnlyCount: number }> = new Map();
    const suspiciousDnsQueries: { packetId: number; name: string; entropy: number; len: number; srcIp: string; dstIp: string }[] = [];
    const entropyCache = new Map<string, number>();

    let telnetCount = 0;
    const telnetIds: number[] = [];
    let telnetSrc = '';
    let telnetDst = '';

    let ftpCount = 0;
    const ftpIds: number[] = [];
    let ftpSrc = '';
    let ftpDst = '';

    const suspiciousPorts = [4444, 1337, 6667, 31337, 8888, 9999];
    const suspiciousPortPackets: { port: number; packet: Packet }[] = [];

    for (let i = 0; i < packets.length; i++) {
      const packet = packets[i];

      if (packet.protocol === 'TCP' && packet.tcpFlags?.syn && !packet.tcpFlags?.ack) {
        const key = `${packet.sourceIp}->${packet.destIp}`;
        let tracker = synScanTracker.get(key);
        if (!tracker && synScanTracker.size < 1000) {
          tracker = { targetIp: packet.destIp, ports: new Set(), packetIds: [], synOnlyCount: 0 };
          synScanTracker.set(key, tracker);
        }
        if (tracker) {
          if (packet.destPort && tracker.ports.size < 100) tracker.ports.add(packet.destPort);
          if (tracker.packetIds.length < 50) tracker.packetIds.push(packet.id);
          tracker.synOnlyCount++;
        }
      }

      if (packet.protocol === 'TELNET') {
        telnetCount++;
        if (telnetIds.length < 50) telnetIds.push(packet.id);
        if (!telnetSrc) {
          telnetSrc = packet.sourceIp;
          telnetDst = packet.destIp;
        }
      }

      if (packet.protocol === 'FTP') {
        ftpCount++;
        if (ftpIds.length < 50) ftpIds.push(packet.id);
        if (!ftpSrc) {
          ftpSrc = packet.sourceIp;
          ftpDst = packet.destIp;
        }
      }

      const pPort = packet.destPort || packet.sourcePort || 0;
      if (suspiciousPorts.includes(pPort) && suspiciousPortPackets.length < 10) {
        suspiciousPortPackets.push({ port: pPort, packet });
      }

      if (packet.protocol === 'DNS' && packet.dnsDetails?.isQuery && packet.dnsDetails.queries) {
        for (const q of packet.dnsDetails.queries) {
          const parts = q.name.split('.');
          const subdomain = parts[0] || '';
          let entropy = entropyCache.get(subdomain);
          if (entropy === undefined) {
            entropy = this.calculateShannonEntropy(subdomain);
            if (entropyCache.size < 500) entropyCache.set(subdomain, entropy);
          }

          if ((subdomain.length >= 25 && entropy >= 3.4) || (q.name.length >= 45 && entropy >= 3.6)) {
            if (suspiciousDnsQueries.length < 50) {
              suspiciousDnsQueries.push({
                packetId: packet.id,
                name: q.name,
                entropy: Number(entropy.toFixed(2)),
                len: q.name.length,
                srcIp: packet.sourceIp,
                dstIp: packet.destIp,
              });
            }
          }
        }
      }
    }

    for (const [key, data] of synScanTracker.entries()) {
      const [srcIp, dstIp] = key.split('->');
      if (data.ports.size >= 4 || data.synOnlyCount >= 8) {
        const portList = Array.from(data.ports).sort((a, b) => a - b);
        addAnomaly({
          title: `Port Scan / Reconnaissance Probe (${data.ports.size} Ports Targeted)`,
          severity: data.ports.size > 8 ? 'critical' : 'high',
          category: 'Port Scan / Reconnaissance',
          protocol: 'TCP',
          sourceIp: srcIp,
          destinationIp: dstIp,
          description: `Host ${srcIp} performed rapid TCP SYN port probing against target ${dstIp}, attempting connection handshakes across ${data.ports.size} distinct ports. This activity matches signature network mapping tools (e.g. Nmap / Masscan) searching for open services.`,
          mitreId: 'T1046',
          mitreTitle: 'Network Service Discovery',
          packetIds: data.packetIds,
          evidence: {
            probedPortsCount: data.ports.size,
            sampleProbedPorts: portList.slice(0, 15).join(', ') + (portList.length > 15 ? '...' : ''),
            totalSynPackets: data.synOnlyCount,
          },
        });
      }
    }

    if (suspiciousDnsQueries.length >= 2) {
      const firstSus = suspiciousDnsQueries[0];
      addAnomaly({
        title: 'DNS Tunneling / Data Exfiltration Anomaly',
        severity: 'critical',
        category: 'DNS Tunneling / Exfiltration',
        protocol: 'DNS',
        sourceIp: firstSus.srcIp,
        destinationIp: firstSus.dstIp,
        description: `Identified ${suspiciousDnsQueries.length} DNS query requests with abnormally high Shannon entropy and unusually long subdomain strings. This traffic pattern strongly suggests DNS covert channel communication or data exfiltration over UDP port 53.`,
        mitreId: 'T1048.003',
        mitreTitle: 'Exfiltration Over Alternative Protocol: DNS Exfiltration',
        packetIds: suspiciousDnsQueries.map(s => s.packetId),
        evidence: {
          suspiciousQueriesCount: suspiciousDnsQueries.length,
          sampleDomain: firstSus.name,
          shannonEntropy: firstSus.entropy,
          subdomainLength: firstSus.len,
        },
      });
    }

    if (telnetCount > 0) {
      addAnomaly({
        title: 'Cleartext Management Protocol In Use: Telnet (Port 23)',
        severity: 'high',
        category: 'Insecure Legacy Protocol',
        protocol: 'TELNET',
        sourceIp: telnetSrc,
        sourcePort: 23,
        destinationIp: telnetDst,
        description: `Host ${telnetSrc} is using unencrypted Telnet protocol for remote shell administration. Telnet sends all keystrokes, administrative credentials, and server responses in plaintext without integrity protection.`,
        mitreId: 'T1040',
        mitreTitle: 'Network Sniffing / Insecure Remote Services',
        packetIds: telnetIds,
        evidence: {
          packetCount: telnetCount,
          port: 23,
          recommendation: 'Decommission Telnet immediately and enforce SSH (Port 22) with key-based authentication.',
        },
      });
    }

    if (ftpCount > 0) {
      addAnomaly({
        title: 'Cleartext File Transfer Protocol In Use: FTP (Port 21)',
        severity: 'medium',
        category: 'Insecure Legacy Protocol',
        protocol: 'FTP',
        sourceIp: ftpSrc,
        sourcePort: 21,
        destinationIp: ftpDst,
        description: `Unencrypted FTP (File Transfer Protocol) detected between ${ftpSrc} and ${ftpDst}. File contents, directory structures, and authentication credentials traverse the wire in cleartext.`,
        mitreId: 'T1040',
        mitreTitle: 'Network Sniffing',
        packetIds: ftpIds,
        evidence: {
          packetCount: ftpCount,
          port: 21,
          recommendation: 'Migrate file transfer workflows to SFTP (SSH File Transfer) or FTPS (TLS).',
        },
      });
    }

    if (suspiciousPortPackets.length > 0) {
      const { port: flaggedPort, packet: p } = suspiciousPortPackets[0];
      addAnomaly({
        title: `Suspicious Non-Standard Port Traffic (Port ${flaggedPort})`,
        severity: 'high',
        category: 'Suspicious Traffic Spike',
        protocol: p.protocol,
        sourceIp: p.sourceIp,
        sourcePort: p.sourcePort,
        destinationIp: p.destIp,
        destinationPort: p.destPort,
        description: `Observed active communication over port ${flaggedPort}, which is commonly associated with reverse shell payloads, IRC botnet command-and-control, or unauthorized backdoor utilities.`,
        mitreId: 'T1571',
        mitreTitle: 'Non-Standard Port',
        packetIds: suspiciousPortPackets.map(item => item.packet.id),
        evidence: {
          flaggedPort,
          protocol: p.protocol,
          recommendation: 'Isolate host endpoint and inspect active processes listening on this port.',
        },
      });
    }

    return anomalies;
  }

  private static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    const freq: Record<string, number> = {};
    for (let i = 0; i < str.length; i++) {
      const ch = str[i];
      freq[ch] = (freq[ch] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;
    for (const ch of Object.keys(freq)) {
      const p = freq[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
