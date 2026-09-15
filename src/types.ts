export type ProtocolType = 'HTTP' | 'HTTPS/TLS' | 'DNS' | 'FTP' | 'TELNET' | 'SMTP' | 'POP3' | 'IMAP' | 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'SSH' | 'OTHER';

export interface Packet {
  id: number;
  timestamp: number; // Unix timestamp in seconds with micro/nano fraction
  relativeTime: number; // Seconds since capture start
  captureLength: number;
  originalLength: number;
  linkType: number; // 1 for Ethernet
  
  // Layer 2
  sourceMac?: string;
  destMac?: string;
  etherType?: string;

  // Layer 3
  ipVersion?: 4 | 6;
  sourceIp: string;
  destIp: string;
  ttl?: number;

  // Layer 4
  protocol: ProtocolType;
  transportProtocol?: 'TCP' | 'UDP' | 'ICMP' | 'ARP' | 'OTHER';
  sourcePort?: number;
  destPort?: number;
  tcpFlags?: {
    syn: boolean;
    ack: boolean;
    fin: boolean;
    rst: boolean;
    psh: boolean;
    urg: boolean;
  };
  seqNumber?: number;
  ackNumber?: number;

  // Layer 7 / Info
  info: string;
  payloadLength: number;
  rawBytes: Uint8Array;
  payloadBytes?: Uint8Array;
  payloadText?: string;
  
  // Decoded Application Layer details
  httpDetails?: {
    isRequest?: boolean;
    method?: string;
    path?: string;
    status?: number;
    statusText?: string;
    headers?: Record<string, string>;
    body?: string;
    contentType?: string;
  };

  dnsDetails?: {
    isQuery: boolean;
    transactionId: number;
    queries: { name: string; type: string }[];
    answers: { name: string; type: string; data: string }[];
  };

  ftpDetails?: {
    isCommand: boolean;
    command?: string;
    argument?: string;
    responseCode?: number;
    responseMessage?: string;
  };

  telnetDetails?: {
    text: string;
  };

  tlsDetails?: {
    sni?: string;
    version?: string;
    handshakeType?: string;
  };

  // Associated security tags
  isCleartext?: boolean;
  anomalyIds?: string[];
}

export type CleartextCategory = 
  | 'Credentials & Passwords'
  | 'Session & Auth Tokens'
  | 'Web Forms & Requests'
  | 'Terminal & Shell Sessions'
  | 'File & Protocol Commands'
  | 'DNS Activity'
  | 'Extracted PII & Keys';

export interface CleartextItem {
  id: string;
  category: CleartextCategory;
  type: 'password' | 'basic_auth' | 'bearer_token' | 'cookie' | 'api_key' | 'email' | 'ftp_cred' | 'telnet_session' | 'form_data' | 'url_param' | 'dns_query' | 'sensitive_text';
  protocol: ProtocolType;
  label: string;
  value: string;
  secondaryValue?: string; // e.g. username when value is password
  sourceIp: string;
  sourcePort?: number;
  destIp: string;
  destPort?: number;
  packetId: number;
  timestamp: number;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  contextSnippet: string;
}

export type AnomalySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityAnomaly {
  id: string;
  title: string;
  severity: AnomalySeverity;
  category: 'Cleartext Transmission' | 'Port Scan / Reconnaissance' | 'DNS Tunneling / Exfiltration' | 'Insecure Legacy Protocol' | 'TCP Anomaly / Flood' | 'Suspicious Traffic Spike' | 'Broadcast Anomaly';
  protocol: string;
  sourceIp: string;
  sourcePort?: number;
  destinationIp: string;
  destinationPort?: number;
  description: string;
  mitreId: string;
  mitreTitle: string;
  packetIds: number[];
  evidence: Record<string, string | number | boolean | string[]>;
  aiAnalysis?: AnomalyAnalysis;
}

export interface AnomalyAnalysis {
  title: string;
  severity: string;
  summary: string;
  threatVector: string;
  mitreAttack: string;
  containmentSteps: string[];
  immediateRisk: string;
  isMockFallback?: boolean;
}

export interface Conversation {
  id: string;
  ipA: string;
  ipB: string;
  portA?: number;
  portB?: number;
  protocol: string;
  packets: number;
  bytes: number;
  startTime: number;
  endTime: number;
}

export interface TrafficStats {
  totalPackets: number;
  totalBytes: number;
  durationSeconds: number;
  startTime: number;
  endTime: number;
  protocolCounts: Record<string, number>;
  protocolBytes: Record<string, number>;
  topTalkers: { ip: string; sentPackets: number; receivedPackets: number; totalBytes: number }[];
  conversations: Conversation[];
  portDistribution: { port: number; service: string; packets: number; bytes: number }[];
  timeBuckets: {
    timeLabel: string;
    timestamp: number;
    totalPackets: number;
    http: number;
    dns: number;
    tcp: number;
    udp: number;
    tls: number;
    other: number;
    bytes: number;
  }[];
}

export interface AnalysisResult {
  filename: string;
  fileSize: number;
  parsedPackets: Packet[];
  cleartextItems: CleartextItem[];
  anomalies: SecurityAnomaly[];
  stats: TrafficStats;
}

export interface PcapParseResult {
  filename: string;
  fileSizeBytes: number;
  packets: Packet[];
  cleartextItems: CleartextItem[];
  anomalies: SecurityAnomaly[];
  stats: TrafficStats;
}
