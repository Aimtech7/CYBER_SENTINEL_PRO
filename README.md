🚨 CYBER SENTINEL PRO

AI-Powered Next-Generation Cybersecurity Automation Suite
An intelligent, modular, and fully extensible Python-based cybersecurity toolkit.

<div align="center">












</div>
🛡️ Overview

Cyber Sentinel Pro is a powerful, AI-augmented cybersecurity suite designed for:

🔍 Real-time monitoring

🧠 AI-assisted threat analysis

🌐 Network scanning & intelligence

🛑 Safe, verified firewall actions

🧪 Malware sandboxing

📊 SIEM-style log ingestion

🔄 Automated security workflows

🎨 Modern, visually appealing GUI

It integrates traditional security tools with modern AI automation to deliver a seamless, intelligent, and interactive cybersecurity experience.

🎨 Release Banner for GitHub

Copy this banner directly into your GitHub README:

<div align="center">
██████╗ ██╗   ██╗██████╗ ███████╗██████╗     ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
██╔══██╗██║   ██║██╔══██╗██╔════╝██╔══██╗    ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
██████╔╝██║   ██║██████╔╝█████╗  ██║  ██║    ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
██╔═══╝ ██║   ██║██╔══██╗██╔══╝  ██║  ██║    ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
██║     ╚██████╔╝██║  ██║███████╗██████╔╝    ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

</div>
🧩 Visual Architecture Diagram
System-Level Architecture (ASCII Diagram – IDE-Friendly)
                                  ┌───────────────────────────┐
                                  │     CYBER SENTINEL PRO    │
                                  │  AI Cybersecurity Suite    │
                                  └──────────────┬────────────┘
                                                 │
        ┌────────────────────────────────────────┼──────────────────────────────────────────┐
        │                                        │                                          │
┌──────────────┐                       ┌─────────────────────┐                     ┌──────────────────┐
│ User Interface│                       │   Automation Engine │                     │ AI Threat Engine │
│ (PyQt6 / CTk) │                       │  (Multithreaded)    │                     │ (OpenAI API)     │
└──────┬────────┘                       └──────────┬──────────┘                     └──────┬──────────┘
       │                                           │                                        │
       │                                           │                                        │
       ▼                                           ▼                                        ▼
┌──────────────┐       ┌───────────────────────┐       ┌──────────────────────┐     ┌─────────────────────┐
│ Navigation UI│       │ Background Automations│       │ AI Explanation Engine│     │ Natural-Language     │
│ Sidebars,Tabs│       │ Log Watch, IP Scan,etc│       │ Risk Scoring         │     │ Threat Queries       │
└──────┬────────┘       └─────────────┬─────────┘     └─────────┬────────────┘     └──────────┬──────────┘
       │                                │                          │                            │
       │                                │                          │                            │
       ▼                                ▼                          ▼                            ▼
┌──────────────┐     ┌────────────────────────────┐     ┌──────────────────────┐     ┌────────────────────────┐
│ Network Tools│     │ Web & Pentest Modules      │     │ Malware Sandbox      │     │ Threat Intelligence APIs│
│ Sniffer,Nmap │     │ Web Scan, Dirbuster, etc   │     │ Hashing, Behavior    │     │ VirusTotal, Shodan,etc │
└──────────────┘     └────────────────────────────┘     └──────────────────────┘     └──────────┬────────────┘
                                                                                                  │
                                                                                                  ▼
                                                                                     ┌────────────────────────┐
                                                                                     │ Firewall Controller     │
                                                                                     │ Safe Block + Verify     │
                                                                                     └────────────────────────┘

✨ Key Features
🔥 1. AI Threat Assistant

Integrated with OpenAI API

Explains threats, logs, anomalies, packets

Recommends security actions

Natural language security queries

Risk scoring + insight generation

🤖 2. Automation Engine

Automated tasks running in background threads:

Log monitoring

Suspicious IP detection

File integrity monitoring

Auto-sandbox scanning

AI-driven risk alerts

Each automation can be Started / Stopped from the GUI.

🌐 3. Network & Web Security Tools

Includes:

WiFi Analyzer & Cracker

Packet Sniffer Dashboard

Nmap-based Network Mapper

Web Vulnerability Scanner

Directory brute-forcer

Port & OS Detection

Fully integrated into the GUI.

🔬 4. Malware Sandbox

SHA256 hashing

Behavior simulation

Metadata extraction

AI summaries of findings

📊 5. Log Analyzer (SIEM-Lite)

Load and parse logs

Detect anomalies

AI-driven threat insights

Beautiful charts and filtering

🌍 6. Threat Intelligence Dashboard

Real-time data from:

VirusTotal

Shodan

AbuseIPDB

With:

AI analysis

“Block IP / Domain” options

Always shows verification prompt before any firewall action

🧱 7. Safe Firewall Controls

Windows (netsh)

Linux (iptables / ufw)

Full block/unblock history

User verification required

🎨 8. Modern GUI

Sidebar navigation

Beautiful dashboards

Dark mode / Light mode

Animated loaders

Styled buttons & cards

Log viewer with highlighting

Built with PyQt6 / CustomTkinter for responsive UI.

📁 Project Structure
CYBER_SENTINEL_PRO/
│
├── core/
│   ├── ai_assistant/
│   ├── automations/
│   ├── network_tools/
│   ├── web_scanner/
│   ├── malware_sandbox/
│   ├── siem_logs/
│   ├── threat_intel/
│   └── firewall/
│
├── ui/
│   ├── main_window.py
│   ├── ai_tab.py
│   ├── automation_tab.py
│   ├── wifi_tab.py
│   ├── sniffer_tab.py
│   ├── webscan_tab.py
│   ├── nmap_tab.py
│   ├── sandbox_tab.py
│   └── threatintel_tab.py
│
├── assets/
│   └── icons/
│
├── requirements.txt
├── config.json
└── main.py

🚀 Installation
1️⃣ Clone the Repository
git clone https://github.com/Aimtech7/CYBER_SENTINEL_PRO.git
cd CYBER_SENTINEL_PRO

2️⃣ Create a Virtual Environment
python -m venv venv
venv\Scripts\activate   # Windows
source venv/bin/activate  # Linux/Mac

3️⃣ Install Dependencies
pip install -r requirements.txt

4️⃣ Add Your OpenAI API Key

Create a .env file:

OPENAI_API_KEY=your_api_key_here

▶️ Running the Application
python main.py

🛠️ How to Use
💠 Navigation

Use the sidebar to switch between modules:

AI Assistant

Automations

WiFi Analyzer

Packet Sniffer

Web Scanner

Nmap Mapper

Sandbox

Threat Intel

💠 Starting Automations

You can start/stop:

Log monitors

IP scanners

File integrity monitors

Sandbox triggers

💠 AI Assistance

Ask questions like:

"Explain this log."
"Is this file malicious?"
"Rate the risk level of 102.xx.xx.xx"

🤝 Contribution

Contributions are highly welcome!

Steps:

Fork the repo

Create a new branch

Commit your changes

Submit a pull request

You can contribute in:

UI improvements

New automation scripts

Threat intel connectors

Code cleanup

Testing & documentation

🗺️ Roadmap
Feature	Status
AI Threat Assistant	✔️ Done
Automation Engine	✔️ Done
Modern GUI	✔️ Done
Packet Sniffer	✔️ Done
Web Scanner	✔️ Done
Sandbox	✔️ Done
Safe Firewall System	✔️ Done
Auto-Updater	⏳ Coming Soon
Mobile App Companion	⏳ Planned
Cloud Dashboard	⏳ Planned
Browser Plugin for Warnings	⏳ Future
📢 Contact & Support

For questions, collaboration, or reporting issues:

📌 GitHub Issues:
https://github.com/Aimtech7/CYBER_SENTINEL_PRO/issues

⭐ If you like this project, please give it a Star!

It helps the project grow and encourages further development 🌟