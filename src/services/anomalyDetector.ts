import { Packet, SecurityAnomaly, CleartextItem } from '../types';

export class AnomalyDetector {
  public static detect(packets: Packet[], cleartextItems: CleartextItem[]): SecurityAnomaly[] {
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
      const packetIds = Array.from(new Set(credItems.map(c => c.packetId)));
      
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
          sampleTypes: Array.from(new Set(credItems.map(c => c.label))),
        },
      });
    }

    // 2. Port Scanning / Network Service Discovery (Horizontal or Vertical Reconnaissance)
    const synScanTracker: Map<string, { targetIp: string; ports: Set<number>; packetIds: number[]; synOnlyCount: number }> = new Map();

    for (const packet of packets) {
      if (packet.protocol === 'TCP' && packet.tcpFlags?.syn && !packet.tcpFlags?.ack) {
        const key = `${packet.sourceIp}->${packet.destIp}`;
        if (!synScanTracker.has(key)) {
          synScanTracker.set(key, { targetIp: packet.destIp, ports: new Set(), packetIds: [], synOnlyCount: 0 });
        }
        const tracker = synScanTracker.get(key)!;
        if (packet.destPort) tracker.ports.add(packet.destPort);
        tracker.packetIds.push(packet.id);
        tracker.synOnlyCount++;
      }
    }

    for (const [key, data] of synScanTracker.entries()) {
      const [srcIp, dstIp] = key.split('->');
      // If 4 or more distinct ports were targeted by SYN probes, or more than 8 rapid SYN packets to a host
      if (data.ports.size >= 4 || data.synOnlyCount >= 8) {
        const portList = Array.from(data.ports).sort((a, b) => a - b);
        addAnomaly({
          title: `Port Scan / Reconnaissance Probe (${portList.length} Ports Targeted)`,
          severity: data.ports.size > 8 ? 'critical' : 'high',
          category: 'Port Scan / Reconnaissance',
          protocol: 'TCP',
          sourceIp: srcIp,
          destinationIp: dstIp,
          description: `Host ${srcIp} performed rapid TCP SYN port probing against target ${dstIp}, attempting connection handshakes across ${data.ports.size} distinct ports. This activity matches signature network mapping tools (e.g. Nmap / Masscan) searching for open services.`,
          mitreId: 'T1046',
          mitreTitle: 'Network Service Discovery',
          packetIds: data.packetIds.slice(0, 50),
          evidence: {
            probedPortsCount: data.ports.size,
            sampleProbedPorts: portList.slice(0, 15).join(', ') + (portList.length > 15 ? '...' : ''),
            totalSynPackets: data.synOnlyCount,
          },
        });
      }
    }

    // 3. DNS Tunneling & High-Entropy Data Exfiltration
    const dnsPackets = packets.filter(p => p.protocol === 'DNS' && p.dnsDetails?.isQuery);
    const suspiciousDnsQueries: { packetId: number; name: string; entropy: number; len: number }[] = [];

    for (const p of dnsPackets) {
      if (p.dnsDetails?.queries) {
        for (const q of p.dnsDetails.queries) {
          const parts = q.name.split('.');
          const subdomain = parts[0] || '';
          const entropy = this.calculateShannonEntropy(subdomain);
          // If subdomain is long (>25 chars) and high entropy (>3.5), or query name exceeds 45 chars
          if ((subdomain.length >= 25 && entropy >= 3.4) || (q.name.length >= 45 && entropy >= 3.6)) {
            suspiciousDnsQueries.push({
              packetId: p.id,
              name: q.name,
              entropy: Number(entropy.toFixed(2)),
              len: q.name.length,
            });
          }
        }
      }
    }

    if (suspiciousDnsQueries.length >= 2) {
      const firstSus = suspiciousDnsQueries[0];
      const packet = packets.find(p => p.id === firstSus.packetId);
      addAnomaly({
        title: 'DNS Tunneling / Data Exfiltration Anomaly',
        severity: 'critical',
        category: 'DNS Tunneling / Exfiltration',
        protocol: 'DNS',
        sourceIp: packet?.sourceIp || 'Unknown',
        destinationIp: packet?.destIp || 'Unknown',
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

    // 4. Insecure Legacy Protocol: Telnet
    const telnetPackets = packets.filter(p => p.protocol === 'TELNET');
    if (telnetPackets.length > 0) {
      const src = telnetPackets[0].sourceIp;
      const dst = telnetPackets[0].destIp;
      addAnomaly({
        title: 'Cleartext Management Protocol In Use: Telnet (Port 23)',
        severity: 'high',
        category: 'Insecure Legacy Protocol',
        protocol: 'TELNET',
        sourceIp: src,
        sourcePort: 23,
        destinationIp: dst,
        description: `Host ${src} is using unencrypted Telnet protocol for remote shell administration. Telnet sends all keystrokes, administrative credentials, and server responses in plaintext without integrity protection.`,
        mitreId: 'T1040',
        mitreTitle: 'Network Sniffing / Insecure Remote Services',
        packetIds: telnetPackets.map(p => p.id),
        evidence: {
          packetCount: telnetPackets.length,
          port: 23,
          recommendation: 'Decommission Telnet immediately and enforce SSH (Port 22) with key-based authentication.',
        },
      });
    }

    // 5. Insecure Legacy Protocol: Unencrypted FTP
    const ftpPackets = packets.filter(p => p.protocol === 'FTP');
    if (ftpPackets.length > 0) {
      const src = ftpPackets[0].sourceIp;
      const dst = ftpPackets[0].destIp;
      addAnomaly({
        title: 'Cleartext File Transfer Protocol In Use: FTP (Port 21)',
        severity: 'medium',
        category: 'Insecure Legacy Protocol',
        protocol: 'FTP',
        sourceIp: src,
        sourcePort: 21,
        destinationIp: dst,
        description: `Unencrypted FTP (File Transfer Protocol) detected between ${src} and ${dst}. File contents, directory structures, and authentication credentials traverse the wire in cleartext.`,
        mitreId: 'T1040',
        mitreTitle: 'Network Sniffing',
        packetIds: ftpPackets.map(p => p.id),
        evidence: {
          packetCount: ftpPackets.length,
          port: 21,
          recommendation: 'Migrate file transfer workflows to SFTP (SSH File Transfer) or FTPS (TLS).',
        },
      });
    }

    // 6. Suspicious Non-Standard Shell / Trojan Ports
    const suspiciousPorts = [4444, 1337, 6667, 31337, 8888, 9999];
    const suspiciousPortPackets = packets.filter(p => 
      (p.destPort && suspiciousPorts.includes(p.destPort)) || 
      (p.sourcePort && suspiciousPorts.includes(p.sourcePort))
    );

    if (suspiciousPortPackets.length > 0) {
      const p = suspiciousPortPackets[0];
      const flaggedPort = suspiciousPorts.find(port => port === p.destPort || port === p.sourcePort) || 0;
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
        packetIds: suspiciousPortPackets.map(pkt => pkt.id),
        evidence: {
          observedPort: flaggedPort,
          packetCount: suspiciousPortPackets.length,
        },
      });
    }

    // 7. Internal Network Name Leakage over Plaintext DNS
    const internalDns = dnsPackets.filter(p => 
      p.dnsDetails?.queries.some(q => /\.local$|\.corp$|\.internal$|\.lan$/i.test(q.name))
    );
    if (internalDns.length > 0) {
      const leakedNames = Array.from(new Set(
        internalDns.flatMap(p => p.dnsDetails?.queries.map(q => q.name) || [])
      ));
      addAnomaly({
        title: 'Internal Corporate Hostname Leakage over DNS',
        severity: 'low',
        category: 'Cleartext Transmission',
        protocol: 'DNS',
        sourceIp: internalDns[0].sourceIp,
        destinationIp: internalDns[0].destIp,
        description: `Unencrypted DNS queries reveal internal corporate infrastructure names (${leakedNames.slice(0, 3).join(', ')}). This leaks internal network topologies, domain controllers, and asset naming conventions to external eavesdroppers.`,
        mitreId: 'T1590',
        mitreTitle: 'Gather Victim Network Information',
        packetIds: internalDns.map(p => p.id),
        evidence: {
          leakedDomains: leakedNames,
          queryCount: internalDns.length,
        },
      });
    }

    return anomalies;
  }

  // Shannon Entropy formula: H(X) = -sum(P(x) * log2(P(x)))
  private static calculateShannonEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    const len = str.length;
    const frequencies: Record<string, number> = {};
    for (let i = 0; i < len; i++) {
      const ch = str[i];
      frequencies[ch] = (frequencies[ch] || 0) + 1;
    }

    let entropy = 0;
    for (const ch in frequencies) {
      const p = frequencies[ch] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }
}
