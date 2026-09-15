# PacketLens 🔍

**PCAP Analyzer & Cleartext Inspector**
*Developed by Me (@ryguitarguy)*

🌐 **Live Web App:** [packetlens.ai.studio](https://packetlens.ai.studio)

## Overview
PacketLens is a fast, entirely in-memory packet capture (PCAP/PCAPNG) analysis tool designed for immediate security triage, forensic investigations, and network visibility. It ingests network traffic, harvests unencrypted data, visualizes communication patterns, and flags potential security anomalies.

## Key Features
*   **In-Memory Binary Parsing:** Decodes classic libpcap and PCAP Next Generation (.pcapng) files. Disassembles multi-layer frame structures (Ethernet II, IPv4, TCP, UDP, ICMP, ARP) and decodes application layers (HTTP, DNS, FTP, Telnet, TLS).
*   **Automated Cleartext Harvesting:** Automatically extracts and categorizes credentials (HTTP Basic Auth, FTP, Telnet passwords), session tokens (JWT, cookies), web forms, terminal sessions, and leaked keys.
*   **Security Anomaly Detection:** Uses behavioral heuristics to detect port scanning, DNS tunneling/data exfiltration, and plaintext credential transmission. Maps findings directly to MITRE ATT&CK technique IDs (e.g., T1552, T1046, T1048).
*   **Network Traffic Visualization:** Interactive capture timelines, protocol hierarchy breakdowns, and active host bandwidth matrices.
*   **Deep Packet Inspection:** Wireshark-grade packet list with dual 16-byte Hex & ASCII dump viewer, protocol filters, and real-time search.

## Forensics & Audit
Export full forensic audit reports as formatted Markdown (`.md`) or structured JSON for incident response documentation.
