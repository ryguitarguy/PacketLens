import express from "express";
import path from "path";
import dotenv from "dotenv";
import { GoogleGenAI } from "@google/genai";
import { createServer as createViteServer } from "vite";

dotenv.config();

let aiClient: GoogleGenAI | null = null;
function getGeminiClient(): GoogleGenAI | null {
  if (!aiClient && process.env.GEMINI_API_KEY) {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          "User-Agent": "aistudio-build",
        },
      },
    });
  }
  return aiClient;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json({ limit: "25mb" }));

  // Health check
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", timestamp: new Date().toISOString() });
  });

  // AI Security Anomaly Analysis & Incident Response Advice
  app.post("/api/gemini/analyze-anomaly", async (req, res) => {
    try {
      const { anomaly, packetContext, conversationContext } = req.body;
      if (!anomaly) {
        return res.status(400).json({ error: "Missing anomaly details" });
      }

      const ai = getGeminiClient();
      if (!ai) {
        return res.json({
          analysis: {
            title: `Forensic Review: ${anomaly.title}`,
            severity: anomaly.severity,
            summary: `Automated detection flagged ${anomaly.title} involving ${anomaly.sourceIp || 'source'} -> ${anomaly.destinationIp || 'destination'}. Protocol: ${anomaly.protocol || 'Unknown'}.`,
            threatVector: "Cleartext transmission or anomalous packet frequency detected without active transport layer encryption.",
            mitreAttack: anomaly.mitreId || "T1040 - Network Sniffing",
            containmentSteps: [
              "Enforce TLS 1.3 / HTTPS across all internal and public service endpoints.",
              "Audit client configuration to eliminate legacy plaintext protocols (HTTP, Telnet, FTP).",
              "Implement Network Access Control (NAC) and firewall ingress/egress filtering rules.",
              "Rotate any potentially compromised credentials exposed in this capture stream."
            ],
            immediateRisk: "High risk of credential interception, session hijacking, or reconnaissance if captured on unsegmented network segments.",
            isMockFallback: true
          }
        });
      }

      const prompt = `You are a Principal Digital Forensics and Incident Response (DFIR) & Network Security Engineer.
Analyze the following network anomaly flagged from a raw PCAP packet capture:

Anomaly Details:
- Title: ${anomaly.title}
- Severity: ${anomaly.severity}
- Category: ${anomaly.category}
- Protocol: ${anomaly.protocol}
- Source: ${anomaly.sourceIp}:${anomaly.sourcePort || ''}
- Destination: ${anomaly.destinationIp}:${anomaly.destinationPort || ''}
- Description: ${anomaly.description}
- Evidence Context: ${JSON.stringify(anomaly.evidence || {})}
${packetContext ? `- Packet Details: ${JSON.stringify(packetContext)}` : ''}
${conversationContext ? `- Conversation Details: ${JSON.stringify(conversationContext)}` : ''}

Provide a structured forensic report containing:
1. Executive Technical Summary (2-3 sentences explaining what occurred)
2. Threat Vector & Attacker Objective (what an adversary is attempting or exploiting)
3. MITRE ATT&CK Mapping (Technique ID and Name)
4. Concrete Containment & Remediation Steps (4 prioritized actionable steps)
5. Risk Assessment (Impact on Confidentiality, Integrity, Availability)

Format your response as a valid JSON object matching this schema:
{
  "title": string,
  "severity": string,
  "summary": string,
  "threatVector": string,
  "mitreAttack": string,
  "containmentSteps": string[],
  "immediateRisk": string
}
Only output the JSON object without markdown fences if possible or clean JSON.`;

      const response = await ai.models.generateContent({
        model: "gemini-3.8-flash",
        contents: prompt,
        config: {
          responseMimeType: "application/json",
          temperature: 0.2,
        },
      });

      const responseText = response.text || "{}";
      try {
        const parsed = JSON.parse(responseText);
        return res.json({ analysis: parsed });
      } catch {
        return res.json({
          analysis: {
            title: anomaly.title,
            severity: anomaly.severity,
            summary: responseText,
            threatVector: "Network transmission vulnerability",
            mitreAttack: anomaly.mitreId || "T1040",
            containmentSteps: [
              "Restrict network segment access",
              "Enforce encrypted channels (TLS/SSH)",
              "Inspect adjacent host traffic for lateral movement"
            ],
            immediateRisk: "Exposure of sensitive traffic"
          }
        });
      }
    } catch (err: unknown) {
      console.error("Gemini analysis error:", err);
      const errMsg = err instanceof Error ? err.message : "Internal error";
      return res.status(500).json({ error: errMsg });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (_req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`PCAP Analyzer server running on http://0.0.0.0:${PORT}`);
  });
}

startServer();
