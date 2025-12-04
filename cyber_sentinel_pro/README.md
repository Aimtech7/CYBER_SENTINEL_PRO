# Cyber Sentinel Pro

A full-featured cybersecurity desktop application built in Python 3.10+ with PyQt6. It includes production-ready modules integrated into a unified interface with OpenAI API support.

## Features

- Modern dark cyber-themed UI with neon accents
- Sidebar navigation and responsive layouts
- Modules:
  - WiFi Analyzer & Cracker (scan, monitor, handshake capture, deauth, wordlist cracking)
  - Packet Sniffer Dashboard (Scapy, protocol filters, hex/ASCII, charts, export)
  - Web Vulnerability Scanner (SQLi, XSS, dir brute-force, crawler, HTML/PDF reports, AI summary)
  - Network Mapper (Nmap GUI) with tables and charts
  - SIEM Log Analyzer (regex heuristics, charts, AI summary)
  - Password Cracking Controller (Hashcat) with live output and export
  - Malware Analysis Sandbox (static analysis, IoCs, AI summary)
- Threat Intelligence Dashboard (VirusTotal, Shodan, AbuseIPDB, OTX; Safe Blocking)
- AI Threat Assistant (chat, explain threats, summarize logs, analyze packets, risk, recommendations)
- Automation Engine (SIEM monitoring, IP reputation, suspicious activity, file integrity, auto-sandbox, AI risk; background threads)
- System Health Dashboard (CPU/RAM/Disk charts with AI commentary)
- Non-blocking threads for long-running tasks
- Settings page with encrypted OpenAI API key storage and Dark Mode toggle

## Project Structure

```
cyber_sentinel_pro/
│── main.py
│── ui/
│   ├── main_window.py
│   ├── wifi_tab.py
│   ├── sniffer_tab.py
│   ├── webscan_tab.py
│   ├── nmap_tab.py
│   ├── siem_tab.py
│   ├── malware_tab.py
│   ├── threatintel_tab.py
│   └── settings_tab.py
│── core/
│   ├── wifi/
│   │   ├── wifi_controller.py
│   │   └── aircrack.py
│   ├── sniffer/
│   │   └── sniffer.py
│   ├── webscan/
│   │   └── webscanner.py
│   ├── nmap/
│   │   └── nmap_client.py
│   ├── siem/
│   │   └── analyzer.py
│   ├── malware/
│   │   └── sandbox.py
│   ├── threatintel/
│   │   └── apis.py
│   └── utils/
│       ├── secure_storage.py
│       └── ai_client.py
│── assets/
│   ├── icons/
│   └── styles/
└── requirements.txt
```

## Setup

1. Install Python 3.10+
2. Create a virtual environment and install dependencies:

```
python -m venv venv
venv\Scripts\activate  # Windows
pip install -r cyber_sentinel_pro/requirements.txt
```

3. Windows prerequisites:
- Install Npcap (required by Scapy): https://npcap.com/
- Install Nmap and ensure `nmap` is in PATH: https://nmap.org/
- Install Hashcat and ensure `hashcat` is in PATH: https://hashcat.net/hashcat/
- For WiFi monitor/deauth/handshake features, aircrack-ng tools require Linux/WSL; scanning works on Windows.

4. Optional: Install Aircrack-ng on Linux/WSL for advanced WiFi features: https://www.aircrack-ng.org/

5. Run the app:

```
python cyber_sentinel_pro/main.py
```

## OpenAI API Key

- Preferred: set `OPENAI_API_KEY` environment variable.
- Or open the Settings tab, paste your OpenAI API key (sk-...), and save. The key is encrypted and stored locally in `~/.cyber_sentinel_pro/settings.json`.

## Safe Blocking (Firewall)

- From Threat Intelligence tab, use `Block IP`/`Unblock IP`.
- Always prompts for confirmation before executing.
- Windows uses `netsh advfirewall` and may require Administrator.
- Linux attempts `ufw` or falls back to `iptables` and may require sudo.

## Automation Engine

- New tab `Automation Engine` exposes start/stop controls per task, status and live logs.
- Settings are stored via app settings; configure paths/IPs in-app.

## System Health

- `System Health` tab shows live CPU/RAM/Disk trends and AI commentary.

## Notes on Capabilities

- Some operations require elevated privileges or OS-specific support (e.g., monitor mode).
- Packet capture requires Npcap on Windows.
- Threat intel features require API keys for VirusTotal, Shodan, and AbuseIPDB (set them in Settings).

## Screenshots

- Add screenshots after running the app:
  - UI Overview
  - Web Scanner Report
  - SIEM Analysis with AI Summary

## Security

- Secrets are never logged.
- API keys are encrypted with a per-user derived key.

## Disclaimer

Use responsibly and legally. Ensure you have authorization for any scanning or testing performed.
