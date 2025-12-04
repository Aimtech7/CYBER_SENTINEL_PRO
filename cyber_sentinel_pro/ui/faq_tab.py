from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QTextEdit
from PyQt6.QtCore import Qt


class FAQTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('FAQ / How To')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)

        doc = QTextEdit()
        doc.setReadOnly(True)
        doc.setMinimumHeight(400)
        doc.setText(
            '\n'.join([
                'WiFi Analyzer: Scan nearby networks, toggle auto-scan, capture handshake, and run cracking with a wordlist.',
                'Packet Sniffer: Start capture to view live packets, apply filters, and export data for analysis.',
                'Web Scanner: Enter target URL, run checks for common vulnerabilities, and review findings.',
                'Network Mapper: Provide host or subnet, run discovery, and inspect open ports and services.',
                'SIEM Analyzer: Load logs (e.g., Suricata eve.json), filter by severity, and generate AI summaries.',
                'Hashcat Controller: Ensure Hashcat is installed and in PATH, select hash file and attack mode to run.',
                'Malware Sandbox: Analyze files statically, inspect strings and metadata; use YARA rules if configured.',
                'Honeypot: Enable listeners on selected ports; monitor inbound connections and suspicious activity.',
                'Threat Intelligence: Query threat feeds and indicators; review IP/domain reputation and recent alerts.',
                'Settings: Save API keys securely, set OpenAI model, and run API tests to verify connectivity.',
                'Tips: Use the Test OpenAI button to verify your key; ensure stable internet and valid model access.',
            ])
        )
        root.addWidget(doc)
        note = QLabel('For detailed workflows, see each tab\'s on-screen controls and labels.')
        note.setAlignment(Qt.AlignmentFlag.AlignLeft)
        root.addWidget(note)
