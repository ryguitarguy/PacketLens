import { Packet, CleartextItem } from '../types';

export class UnencryptedScanner {
  public static scan(packets: Packet[]): CleartextItem[] {
    const items: CleartextItem[] = [];
    let itemIdCounter = 1;

    // Helper to add item
    const addItem = (item: Omit<CleartextItem, 'id'>) => {
      items.push({
        id: `cleartext-${itemIdCounter++}`,
        ...item,
      });
    };

    // Track Telnet sessions by IP pair to reconstruct shell dialog
    const telnetStreams: Map<string, { packets: Packet[]; text: string }> = new Map();

    for (const packet of packets) {
      // 1. HTTP Inspection
      if (packet.protocol === 'HTTP' && packet.httpDetails) {
        const http = packet.httpDetails;
        const headers = http.headers || {};

        // 1a. Authorization Header (Basic Auth / Bearer)
        const authHeader = headers['authorization'];
        if (authHeader) {
          if (authHeader.toLowerCase().startsWith('basic ')) {
            const b64 = authHeader.substring(6).trim();
            let decoded = '';
            try {
              decoded = atob(b64);
            } catch {
              decoded = b64;
            }
            const [user, pass] = decoded.includes(':') ? decoded.split(/:(.*)/s) : [decoded, ''];
            addItem({
              category: 'Credentials & Passwords',
              type: 'basic_auth',
              protocol: 'HTTP',
              label: 'HTTP Basic Auth Decoded',
              value: pass || decoded,
              secondaryValue: user ? `User: ${user}` : undefined,
              sourceIp: packet.sourceIp,
              sourcePort: packet.sourcePort,
              destIp: packet.destIp,
              destPort: packet.destPort,
              packetId: packet.id,
              timestamp: packet.timestamp,
              riskLevel: 'critical',
              contextSnippet: `Authorization: Basic ${b64} -> Decoded: ${decoded} (${http.method || ''} ${http.path || ''})`,
            });
          } else if (authHeader.toLowerCase().startsWith('bearer ')) {
            const token = authHeader.substring(7).trim();
            addItem({
              category: 'Session & Auth Tokens',
              type: 'bearer_token',
              protocol: 'HTTP',
              label: 'Cleartext Bearer Token',
              value: token,
              sourceIp: packet.sourceIp,
              sourcePort: packet.sourcePort,
              destIp: packet.destIp,
              destPort: packet.destPort,
              packetId: packet.id,
              timestamp: packet.timestamp,
              riskLevel: 'high',
              contextSnippet: `Authorization: Bearer ${token.substring(0, 32)}... (${http.method || ''} ${http.path || ''})`,
            });
          }
        }

        // 1b. Cookies
        const cookieHeader = headers['cookie'] || headers['set-cookie'];
        if (cookieHeader) {
          const cookiePairs = cookieHeader.split(';').map(c => c.trim());
          for (const pair of cookiePairs) {
            const [cKey, cVal] = pair.split('=');
            if (cKey && cVal) {
              const lowerKey = cKey.toLowerCase();
              const isSensitive = /session|token|auth|jwt|phpsessid|jsessionid|admin|user|key/.test(lowerKey);
              if (isSensitive) {
                addItem({
                  category: 'Session & Auth Tokens',
                  type: 'cookie',
                  protocol: 'HTTP',
                  label: `Session Cookie (${cKey.trim()})`,
                  value: cVal.trim(),
                  secondaryValue: `Cookie Name: ${cKey.trim()}`,
                  sourceIp: packet.sourceIp,
                  sourcePort: packet.sourcePort,
                  destIp: packet.destIp,
                  destPort: packet.destPort,
                  packetId: packet.id,
                  timestamp: packet.timestamp,
                  riskLevel: 'high',
                  contextSnippet: `Cookie: ${pair} on ${http.method || ''} ${http.path || ''}`,
                });
              }
            }
          }
        }

        // 1c. HTTP Form Body & Passwords
        if (http.body) {
          const body = http.body;

          // Check url-encoded form data (e.g. username=admin&password=secret)
          if (body.includes('=') && (body.includes('&') || body.length < 500)) {
            const params = new URLSearchParams(body.replace(/\r?\n.*/s, ''));
            const username = params.get('username') || params.get('user') || params.get('login') || params.get('email');
            const password = params.get('password') || params.get('pass') || params.get('pwd') || params.get('passwd');

            if (password) {
              addItem({
                category: 'Credentials & Passwords',
                type: 'password',
                protocol: 'HTTP',
                label: 'HTTP Form Password',
                value: password,
                secondaryValue: username ? `Username: ${username}` : undefined,
                sourceIp: packet.sourceIp,
                sourcePort: packet.sourcePort,
                destIp: packet.destIp,
                destPort: packet.destPort,
                packetId: packet.id,
                timestamp: packet.timestamp,
                riskLevel: 'critical',
                contextSnippet: `POST ${http.path || ''} Payload: user=${username || '<empty>'}, password=${password}`,
              });
            } else if (username) {
              addItem({
                category: 'Web Forms & Requests',
                type: 'form_data',
                protocol: 'HTTP',
                label: 'HTTP Form Username / Login',
                value: username,
                sourceIp: packet.sourceIp,
                sourcePort: packet.sourcePort,
                destIp: packet.destIp,
                destPort: packet.destPort,
                packetId: packet.id,
                timestamp: packet.timestamp,
                riskLevel: 'medium',
                contextSnippet: `Form field user=${username} on ${http.path || ''}`,
              });
            }
          }

          // Check JSON body if applicable
          if (body.trim().startsWith('{') && body.trim().endsWith('}')) {
            try {
              const parsed = JSON.parse(body);
              const findKeys = (obj: any) => {
                if (!obj || typeof obj !== 'object') return;
                for (const k of Object.keys(obj)) {
                  const val = obj[k];
                  const lowerK = k.toLowerCase();
                  if (typeof val === 'string') {
                    if (/pass|pwd|secret|key|token|auth/.test(lowerK)) {
                      addItem({
                        category: 'Credentials & Passwords',
                        type: 'password',
                        protocol: 'HTTP',
                        label: `JSON Key: ${k}`,
                        value: val,
                        sourceIp: packet.sourceIp,
                        sourcePort: packet.sourcePort,
                        destIp: packet.destIp,
                        destPort: packet.destPort,
                        packetId: packet.id,
                        timestamp: packet.timestamp,
                        riskLevel: 'critical',
                        contextSnippet: `JSON field "${k}": "${val.substring(0, 50)}" on ${http.path || ''}`,
                      });
                    }
                  } else if (typeof val === 'object') {
                    findKeys(val);
                  }
                }
              };
              findKeys(parsed);
            } catch {
              // Ignore json parse error
            }
          }
        }

        // 1d. HTTP Request Path with query credentials
        if (http.path && http.path.includes('?')) {
          const queryString = http.path.split('?')[1] || '';
          const urlParams = new URLSearchParams(queryString);
          for (const [pKey, pVal] of urlParams.entries()) {
            const lowerP = pKey.toLowerCase();
            if (/pass|key|token|auth|secret|credential|api_key/.test(lowerP)) {
              addItem({
                category: 'Credentials & Passwords',
                type: 'url_param',
                protocol: 'HTTP',
                label: `URL Query Credential (${pKey})`,
                value: pVal,
                secondaryValue: `Endpoint: ${http.path.split('?')[0]}`,
                sourceIp: packet.sourceIp,
                sourcePort: packet.sourcePort,
                destIp: packet.destIp,
                destPort: packet.destPort,
                packetId: packet.id,
                timestamp: packet.timestamp,
                riskLevel: 'critical',
                contextSnippet: `GET ${http.path}`,
              });
            }
          }
        }
      }

      // 2. FTP Inspection
      if (packet.protocol === 'FTP' && packet.ftpDetails) {
        const ftp = packet.ftpDetails;
        if (ftp.isCommand) {
          const cmd = ftp.command || '';
          const arg = ftp.argument || '';
          if (cmd === 'USER') {
            addItem({
              category: 'Credentials & Passwords',
              type: 'ftp_cred',
              protocol: 'FTP',
              label: 'FTP Plaintext Username',
              value: arg,
              sourceIp: packet.sourceIp,
              sourcePort: packet.sourcePort,
              destIp: packet.destIp,
              destPort: packet.destPort,
              packetId: packet.id,
              timestamp: packet.timestamp,
              riskLevel: 'high',
              contextSnippet: `FTP Command: USER ${arg}`,
            });
          } else if (cmd === 'PASS') {
            addItem({
              category: 'Credentials & Passwords',
              type: 'ftp_cred',
              protocol: 'FTP',
              label: 'FTP Plaintext Password',
              value: arg,
              sourceIp: packet.sourceIp,
              sourcePort: packet.sourcePort,
              destIp: packet.destIp,
              destPort: packet.destPort,
              packetId: packet.id,
              timestamp: packet.timestamp,
              riskLevel: 'critical',
              contextSnippet: `FTP Command: PASS ${arg}`,
            });
          } else if (cmd === 'RETR' || cmd === 'STOR') {
            addItem({
              category: 'File & Protocol Commands',
              type: 'sensitive_text',
              protocol: 'FTP',
              label: `FTP File Transfer (${cmd})`,
              value: arg,
              sourceIp: packet.sourceIp,
              sourcePort: packet.sourcePort,
              destIp: packet.destIp,
              destPort: packet.destPort,
              packetId: packet.id,
              timestamp: packet.timestamp,
              riskLevel: 'medium',
              contextSnippet: `FTP ${cmd} ${arg}`,
            });
          }
        }
      }

      // 3. Telnet Session Accumulator
      if (packet.protocol === 'TELNET' && packet.telnetDetails) {
        const clean = packet.telnetDetails.text.trim();
        if (clean.length > 0) {
          const streamKey = `${packet.sourceIp}:${packet.sourcePort} <-> ${packet.destIp}:${packet.destPort}`;
          if (!telnetStreams.has(streamKey)) {
            telnetStreams.set(streamKey, { packets: [], text: '' });
          }
          const s = telnetStreams.get(streamKey)!;
          s.packets.push(packet);
          s.text += (s.text ? ' ' : '') + clean;

          // Check for prompt or passwords
          if (/login:|username:|password:/i.test(clean) || packet.destPort === 23) {
            addItem({
              category: 'Terminal & Shell Sessions',
              type: 'telnet_session',
              protocol: 'TELNET',
              label: 'Telnet Plaintext Terminal Activity',
              value: clean,
              sourceIp: packet.sourceIp,
              sourcePort: packet.sourcePort,
              destIp: packet.destIp,
              destPort: packet.destPort,
              packetId: packet.id,
              timestamp: packet.timestamp,
              riskLevel: /password/i.test(clean) ? 'critical' : 'high',
              contextSnippet: `Telnet Stream: ${clean}`,
            });
          }
        }
      }

      // 4. DNS Queries (Cleartext domain lookups)
      if (packet.protocol === 'DNS' && packet.dnsDetails && packet.dnsDetails.isQuery) {
        for (const q of packet.dnsDetails.queries) {
          const isInternal = /\.local$|\.internal$|\.corp$|\.lan$/i.test(q.name) || /admin|vpn|vault|db|database|ldap|dc01/i.test(q.name);
          addItem({
            category: 'DNS Activity',
            type: 'dns_query',
            protocol: 'DNS',
            label: `DNS Query (${q.type})`,
            value: q.name,
            secondaryValue: `Type: ${q.type}`,
            sourceIp: packet.sourceIp,
            sourcePort: packet.sourcePort,
            destIp: packet.destIp,
            destPort: packet.destPort,
            packetId: packet.id,
            timestamp: packet.timestamp,
            riskLevel: isInternal ? 'high' : 'low',
            contextSnippet: `Client ${packet.sourceIp} requested ${q.type} record for ${q.name}`,
          });
        }
      }

      // 5. Pattern heuristics on raw payload text (Emails, Private Keys, JWTs, AWS Keys)
      if (packet.payloadText && packet.protocol !== 'HTTPS/TLS') {
        const text = packet.payloadText;

        // AWS Access Key Pattern (AKIA...)
        const awsMatch = text.match(/\b(AKIA[0-9A-Z]{16})\b/);
        if (awsMatch) {
          addItem({
            category: 'Extracted PII & Keys',
            type: 'api_key',
            protocol: packet.protocol,
            label: 'AWS Access Key ID Detected',
            value: awsMatch[1],
            sourceIp: packet.sourceIp,
            sourcePort: packet.sourcePort,
            destIp: packet.destIp,
            destPort: packet.destPort,
            packetId: packet.id,
            timestamp: packet.timestamp,
            riskLevel: 'critical',
            contextSnippet: `Matched AWS Key pattern: ${awsMatch[1]}`,
          });
        }

        // Private Key Pattern
        if (text.includes('-----BEGIN PRIVATE KEY-----') || text.includes('-----BEGIN RSA PRIVATE KEY-----')) {
          addItem({
            category: 'Extracted PII & Keys',
            type: 'sensitive_text',
            protocol: packet.protocol,
            label: 'Unencrypted Private Key Block',
            value: '-----BEGIN PRIVATE KEY----- ...',
            sourceIp: packet.sourceIp,
            sourcePort: packet.sourcePort,
            destIp: packet.destIp,
            destPort: packet.destPort,
            packetId: packet.id,
            timestamp: packet.timestamp,
            riskLevel: 'critical',
            contextSnippet: `Cryptographic private key transmitted in plaintext!`,
          });
        }

        // Email address heuristic (avoid false positives on domain names)
        const emailMatches = text.match(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g);
        if (emailMatches && emailMatches.length > 0) {
          // Limit to first 2 emails per packet
          for (const email of emailMatches.slice(0, 2)) {
            // Filter out common code snippets
            if (!email.endsWith('.png') && !email.endsWith('.jpg') && !email.includes('example.invalid')) {
              addItem({
                category: 'Extracted PII & Keys',
                type: 'email',
                protocol: packet.protocol,
                label: 'Cleartext Email Address',
                value: email,
                sourceIp: packet.sourceIp,
                sourcePort: packet.sourcePort,
                destIp: packet.destIp,
                destPort: packet.destPort,
                packetId: packet.id,
                timestamp: packet.timestamp,
                riskLevel: 'medium',
                contextSnippet: `Found email: ${email}`,
              });
            }
          }
        }
      }
    }

    // Deduplicate identical items within same packet
    const seen = new Set<string>();
    const deduped: CleartextItem[] = [];
    for (const it of items) {
      const key = `${it.category}:${it.label}:${it.value}:${it.packetId}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduped.push(it);
      }
    }

    return deduped;
  }
}
