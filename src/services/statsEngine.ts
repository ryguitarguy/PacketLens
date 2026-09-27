import { Packet, TrafficStats, Conversation } from '../types';

export class StatsEngine {
  public static async computeAsync(
    packets: Packet[],
    onProgress?: (p: { percent: number }) => void,
    shouldAbort?: () => boolean
  ): Promise<TrafficStats> {
    if (packets.length === 0) {
      return this.emptyStats();
    }

    const totalCount = packets.length;
    let totalBytes = 0;
    const protocolCounts: Record<string, number> = {};
    const protocolBytes: Record<string, number> = {};
    const ipMap: Map<string, { sent: number; received: number; bytes: number }> = new Map();
    const convMap: Map<string, Conversation> = new Map();
    const portMap: Map<number, { packets: number; bytes: number; service: string }> = new Map();

    const startTime = packets[0].timestamp;
    const endTime = packets[totalCount - 1].timestamp;
    const durationSeconds = Math.max(0.1, Number((endTime - startTime).toFixed(2)));

    // Pre-initialize time buckets for single-pass processing
    const bucketCount = Math.min(24, Math.max(8, Math.ceil(durationSeconds)));
    const bucketDuration = durationSeconds / bucketCount;
    const timeBuckets: TrafficStats['timeBuckets'] = [];

    for (let i = 0; i < bucketCount; i++) {
      const bStart = startTime + i * bucketDuration;
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

    let lastYieldTime = performance.now();

    // Single-pass async processing with time-budgeted event-loop yields
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

      const pkt = packets[i];
      const pktLen = pkt.originalLength || pkt.captureLength;
      totalBytes += pktLen;

      // 1. Protocol stats
      const proto = pkt.protocol;
      protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
      protocolBytes[proto] = (protocolBytes[proto] || 0) + pktLen;

      // 2. Host stats (capped to 2,000 unique hosts to prevent memory bloat during massive port scans)
      const src = pkt.sourceIp;
      const dst = pkt.destIp;

      if (src && src !== '0.0.0.0') {
        let sEntry = ipMap.get(src);
        if (!sEntry && ipMap.size < 2000) {
          sEntry = { sent: 0, received: 0, bytes: 0 };
          ipMap.set(src, sEntry);
        }
        if (sEntry) {
          sEntry.sent++;
          sEntry.bytes += pktLen;
        }
      }

      if (dst && dst !== '0.0.0.0') {
        let dEntry = ipMap.get(dst);
        if (!dEntry && ipMap.size < 2000) {
          dEntry = { sent: 0, received: 0, bytes: 0 };
          ipMap.set(dst, dEntry);
        }
        if (dEntry) {
          dEntry.received++;
          dEntry.bytes += pktLen;
        }
      }

      // 3. Conversation stats (capped to 5,000 unique conversation pairs)
      if (src && dst && src !== '0.0.0.0' && dst !== '0.0.0.0') {
        const isSrcFirst = src < dst;
        const ipA = isSrcFirst ? src : dst;
        const ipB = isSrcFirst ? dst : src;
        const convKey = `${ipA}<->${ipB}:${pkt.protocol}`;

        let c = convMap.get(convKey);
        if (!c && convMap.size < 5000) {
          c = {
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
          };
          convMap.set(convKey, c);
        }
        if (c) {
          c.packets++;
          c.bytes += pktLen;
          c.endTime = pkt.timestamp;
        }
      }

      // 4. Port stats
      const targetPort = pkt.destPort;
      if (targetPort) {
        let pEntry = portMap.get(targetPort);
        if (!pEntry && portMap.size < 500) {
          pEntry = { packets: 0, bytes: 0, service: this.getServiceName(targetPort) };
          portMap.set(targetPort, pEntry);
        }
        if (pEntry) {
          pEntry.packets++;
          pEntry.bytes += pktLen;
        }
      }

      // 5. Time bucket stats in same single pass
      const bIdx = Math.min(
        bucketCount - 1,
        Math.max(0, Math.floor((pkt.timestamp - startTime) / bucketDuration))
      );
      const b = timeBuckets[bIdx];
      if (b) {
        b.totalPackets++;
        b.bytes += pktLen;
        if (proto === 'HTTP') b.http++;
        else if (proto === 'DNS') b.dns++;
        else if (proto === 'HTTPS/TLS') b.tls++;
        else if (proto === 'TCP') b.tcp++;
        else if (proto === 'UDP') b.udp++;
        else b.other++;
      }
    }

    onProgress?.({ percent: 100 });

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

    return {
      totalPackets: totalCount,
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

  public static compute(packets: Packet[]): TrafficStats {
    if (packets.length === 0) return this.emptyStats();

    let totalBytes = 0;
    const protocolCounts: Record<string, number> = {};
    const protocolBytes: Record<string, number> = {};
    const ipMap: Map<string, { sent: number; received: number; bytes: number }> = new Map();
    const convMap: Map<string, Conversation> = new Map();
    const portMap: Map<number, { packets: number; bytes: number; service: string }> = new Map();

    const startTime = packets[0].timestamp;
    const endTime = packets[packets.length - 1].timestamp;
    const durationSeconds = Math.max(0.1, Number((endTime - startTime).toFixed(2)));

    const bucketCount = Math.min(24, Math.max(8, Math.ceil(durationSeconds)));
    const bucketDuration = durationSeconds / bucketCount;
    const timeBuckets: TrafficStats['timeBuckets'] = [];

    for (let i = 0; i < bucketCount; i++) {
      const bStart = startTime + i * bucketDuration;
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
      const pktLen = pkt.originalLength || pkt.captureLength;
      totalBytes += pktLen;

      const proto = pkt.protocol;
      protocolCounts[proto] = (protocolCounts[proto] || 0) + 1;
      protocolBytes[proto] = (protocolBytes[proto] || 0) + pktLen;

      const src = pkt.sourceIp;
      const dst = pkt.destIp;

      if (src && src !== '0.0.0.0') {
        let sEntry = ipMap.get(src);
        if (!sEntry && ipMap.size < 2000) {
          sEntry = { sent: 0, received: 0, bytes: 0 };
          ipMap.set(src, sEntry);
        }
        if (sEntry) {
          sEntry.sent++;
          sEntry.bytes += pktLen;
        }
      }

      if (dst && dst !== '0.0.0.0') {
        let dEntry = ipMap.get(dst);
        if (!dEntry && ipMap.size < 2000) {
          dEntry = { sent: 0, received: 0, bytes: 0 };
          ipMap.set(dst, dEntry);
        }
        if (dEntry) {
          dEntry.received++;
          dEntry.bytes += pktLen;
        }
      }

      if (src && dst && src !== '0.0.0.0' && dst !== '0.0.0.0') {
        const isSrcFirst = src < dst;
        const ipA = isSrcFirst ? src : dst;
        const ipB = isSrcFirst ? dst : src;
        const convKey = `${ipA}<->${ipB}:${pkt.protocol}`;

        let c = convMap.get(convKey);
        if (!c && convMap.size < 5000) {
          c = {
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
          };
          convMap.set(convKey, c);
        }
        if (c) {
          c.packets++;
          c.bytes += pktLen;
          c.endTime = pkt.timestamp;
        }
      }

      const targetPort = pkt.destPort;
      if (targetPort) {
        let pEntry = portMap.get(targetPort);
        if (!pEntry && portMap.size < 500) {
          pEntry = { packets: 0, bytes: 0, service: this.getServiceName(targetPort) };
          portMap.set(targetPort, pEntry);
        }
        if (pEntry) {
          pEntry.packets++;
          pEntry.bytes += pktLen;
        }
      }

      const bIdx = Math.min(
        bucketCount - 1,
        Math.max(0, Math.floor((pkt.timestamp - startTime) / bucketDuration))
      );
      const b = timeBuckets[bIdx];
      if (b) {
        b.totalPackets++;
        b.bytes += pktLen;
        if (proto === 'HTTP') b.http++;
        else if (proto === 'DNS') b.dns++;
        else if (proto === 'HTTPS/TLS') b.tls++;
        else if (proto === 'TCP') b.tcp++;
        else if (proto === 'UDP') b.udp++;
        else b.other++;
      }
    }

    const topTalkers = Array.from(ipMap.entries())
      .map(([ip, data]) => ({
        ip,
        sentPackets: data.sent,
        receivedPackets: data.received,
        totalBytes: data.bytes,
      }))
      .sort((a, b) => b.totalBytes - a.totalBytes)
      .slice(0, 10);

    const conversations = Array.from(convMap.values())
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 20);

    const portDistribution = Array.from(portMap.entries())
      .map(([port, data]) => ({
        port,
        service: data.service,
        packets: data.packets,
        bytes: data.bytes,
      }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 10);

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

  private static emptyStats(): TrafficStats {
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

  private static getServiceName(port: number): string {
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
  }
}
