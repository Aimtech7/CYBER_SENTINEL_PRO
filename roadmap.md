Cyber Sentinel Pro – Roadmap and Change Log

Overview
- PyQt6 desktop app with modular cybersecurity tools and secure settings.
- Non-blocking workers for long operations; integrated AI summaries and reports.

Implemented Modules
- WiFi Analyzer: scanning, handshake capture, auto-scan, auto-crack.
- Packet Sniffer: live capture, filters, export.
- Web Scanner: common vuln checks and reporting.
- Network Mapper: host/subnet discovery, ports/services.
- SIEM Analyzer: log parsing (incl. Suricata), filtering, AI summaries.
- Hashcat Controller: external binary orchestration, errors surfaced.
- Malware Sandbox: static analysis, strings/metadata; YARA support.
- Honeypot: multi-port listeners, connection logging.
- Threat Intelligence: feed integrations (e.g., URLhaus), indicator lookups.

Security and Reliability
- Secure API storage via Fernet with PBKDF2 key derivation.
- Atomic writes with backup to prevent data loss.
- .gitignore excludes secrets and local artifacts.
- OpenAI client retries with exponential backoff.
- Auto-select OpenAI model when unset or unknown.

UI/UX Improvements
- Sidebar/stack alignment fix for tab ordering (Honeypot vs. Threat Intel).
- FAQ tab added with concise tool usage guidance.
- Settings tab supports API testing and model auto-selection.

Known Integrations
- Scapy for packet capture.
- python-nmap for network mapping.
- Aircrack-ng workflow for WiFi cracking.
- OpenAI for summaries and assistant features.

Next Enhancements (tracked separately)
- Endpoint forensics and baseline compare with psutil.
- Report builder for consolidated PDF exports.
- Scheduler (APScheduler) for routine scans.
- Extended MITRE ATT&CK mapping utilities.

Testing
- Import checks across modules and UI.
- API probe for OpenAI validates connectivity and model access.

Notes
- Leave the OpenAI model field blank to let the app auto-select from available models on your account.
