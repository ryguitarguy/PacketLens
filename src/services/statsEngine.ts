import { Packet, TrafficStats, Conversation } from '../types';

export class StatsEngine {
  public static compute(packets: Packet[]): TrafficStats {
    if (packets.length === 0) {
      return {
        totalPackets: 0,
        totalBytes: 0,
        durationSeconds: 0,
        startTime: 0,
        endTime: 0,
        protocolCounts: {},
        protocolBytes: {},
        topTalkers: [],
        conversations: [],
        portDistribution: [],
        timeBuckets: [],
      };
    }

    let totalBytes = 0;
    const protocolCounts: Record<string, number> = {};
    const protocolBytes: Record<string, number> = {};
    const ipMap: Map<string, { sent: number; received: number; bytes: number }> = new Map();
    const convMap: Map<string, Conversation> = new Map();
    const portMap: Map<number, { packets: number; bytes: number; service: string }> = new Map();

    const startTime = packets[0].timestamp;
    const endTime = packets[packets.length - 1].timestamp;
    const durationSeconds = Math.max(0.1, Number((endTime - startTime).toFixed(2)));

    // Well-known port mappings
    const getServiceName = (port: number): string => {
      switch (port) {
        case 80: return 'HTTP';
        case 443: return 'HTTPS/TLS';
        case 53: return 'DNS';
        case 21: return 'FTP Control';
        case 20: return 'FTP Data';
        case 22: return 'SSH';
        case 23: return 'Telnet';
        case 25: return 'SMTP';
        case 110: return 'POP3';
        case 143: return 'IMAP';
        case 445: return 'SMB';
        case 3389: return 'RDP';
        case 8080: return 'HTTP-Alt';
        case 4444: return 'Metasploit Shell';
        default: return port < 1024 ? `Privileged (${port})` : `Port ${port}`;
      }
    };

    for (const pkt of packets) {
      const pktLen = pkt.originalLength || pkt.captureLength;
      totalBytes += pktLen;

      // Protocol stats
      const proto = pkt.protocol;
      protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
      protocolBytes[proto] = (protocolBytes[proto] || 0) + pktLen;

      // Host stats
      const src = pkt.sourceIp;
      const dst = pkt.destIp;

      if (src && src !== '0.0.0.0') {
        if (!ipMap.has(src)) ipMap.set(src, { sent: 0, received: 0, bytes: 0 });
        const sEntry = ipMap.get(src)!;
        sEntry.sent++;
        sEntry.bytes += pktLen;
      }

      if (dst && dst !== '0.0.0.0') {
        if (!ipMap.has(dst)) ipMap.set(dst, { sent: 0, received: 0, bytes: 0 });
        const dEntry = ipMap.get(dst)!;
        dEntry.received++;
        dEntry.bytes += pktLen;
      }

      // Conversation stats
      if (src && dst && src !== '0.0.0.0' && dst !== '0.0.0.0') {
        // Order canonical key
        const isSrcFirst = src < dst;
        const ipA = isSrcFirst ? src : dst;
        const ipB = isSrcFirst ? dst : src;
        const convKey = `${ipA}<->${ipB}:${pkt.protocol}`;

        if (!convMap.has(convKey)) {
          convMap.set(convKey, {
            id: convKey,
            ipA,
            ipB,
            portA: isSrcFirst ? pkt.sourcePort : pkt.destPort,
            portB: isSrcFirst ? pkt.destPort : pkt.sourcePort,
            protocol: pkt.protocol,
            packets: 0,
            bytes: 0,
            startTime: pkt.timestamp,
            endTime: pkt.timestamp,
          });
        }
        const c = convMap.get(convKey)!;
        c.packets++;
        c.bytes += pktLen;
        c.endTime = pkt.timestamp;
      }

      // Port stats (Track destination port for service classification)
      const targetPort = pkt.destPort;
      if (targetPort) {
        if (!portMap.has(targetPort)) {
          portMap.set(targetPort, { packets: 0, bytes: 0, service: getServiceName(targetPort) });
        }
        const pEntry = portMap.get(targetPort)!;
        pEntry.packets++;
        pEntry.bytes += pktLen;
      }
    }

    // Top talkers sorted by total bytes
    const topTalkers = Array.from(ipMap.entries())
      .map(([ip, data]) => ({
        ip,
        sentPackets: data.sent,
        receivedPackets: data.received,
        totalBytes: data.bytes,
      }))
      .sort((a, b) => b.totalBytes - a.totalBytes)
      .slice(0, 10);

    // Conversations sorted by total packets
    const conversations = Array.from(convMap.values())
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 20);

    // Top ports
    const portDistribution = Array.from(portMap.entries())
      .map(([port, data]) => ({
        port,
        service: data.service,
        packets: data.packets,
        bytes: data.bytes,
      }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 10);

    // Time buckets for traffic visualization
    const bucketCount = Math.min(24, Math.max(8, Math.ceil(durationSeconds)));
    const bucketDuration = durationSeconds / bucketCount;
    const timeBuckets: TrafficStats['timeBuckets'] = [];

    for (let i = 0; i < bucketCount; i++) {
      const bStart = startTime + i * bucketDuration;
      const bEnd = bStart + bucketDuration;
      const offsetSeconds = Number((i * bucketDuration).toFixed(1));

      timeBuckets.push({
        timeLabel: `+${offsetSeconds}s`,
        timestamp: bStart,
        totalPackets: 0,
        http: 0,
        dns: 0,
        tcp: 0,
        udp: 0,
        tls: 0,
        other: 0,
        bytes: 0,
      });
    }

    for (const pkt of packets) {
      const idx = Math.min(
        bucketCount - 1,
        Math.max(0, Math.floor((pkt.timestamp - startTime) / bucketDuration))
      );
      const b = timeBuckets[idx];
      if (b) {
        b.totalPackets++;
        b.bytes += (pkt.originalLength || pkt.captureLength);
        if (pkt.protocol === 'HTTP') b.http++;
        else if (pkt.protocol === 'DNS') b.dns++;
        else if (pkt.protocol === 'HTTPS/TLS') b.tls++;
        else if (pkt.protocol === 'TCP') b.tcp++;
        else if (pkt.protocol === 'UDP') b.udp++;
        else b.other++;
      }
    }

    return {
      totalPackets: packets.length,
      totalBytes,
      durationSeconds,
      startTime,
      endTime,
      protocolCounts,
      protocolBytes,
      topTalkers,
      conversations,
      portDistribution,
      timeBuckets,
    };
  }
}
