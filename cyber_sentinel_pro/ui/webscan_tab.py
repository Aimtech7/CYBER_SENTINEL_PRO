import os
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QFileDialog
)
from core.webscan.webscanner import WebScanner
from core.utils.ai_client import summarize
from core.utils.attack_map import enrich_findings


class WebScanWorker(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(object)

    def __init__(self, base: str):
        super().__init__()
        self.base = base

    def run(self):
        sc = WebScanner(self.base)
        sc.crawler(max_pages=30)
        for u in list(sc.crawled)[:20]:
            sc.test_sql_injection(u)
            sc.test_xss(u)
        sc.dir_bruteforce(['admin', 'login', 'uploads', 'backup', '.git'])
        self.done.emit(sc)


class WebScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.worker = None

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Web Vulnerability Scanner')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        self.url_edit = QLineEdit(); self.url_edit.setPlaceholderText('https://target.example')
        start_btn = QPushButton('Run Scan')
        export_html_btn = QPushButton('Export HTML')
        export_pdf_btn = QPushButton('Export PDF')
        top.addWidget(self.url_edit)
        top.addWidget(start_btn)
        top.addWidget(export_html_btn)
        top.addWidget(export_pdf_btn)
        root.addLayout(top)

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)

        self.scanner = None

        start_btn.clicked.connect(self.start_scan)
        export_html_btn.clicked.connect(self.export_html)
        export_pdf_btn.clicked.connect(self.export_pdf)

    def start_scan(self):
        url = self.url_edit.text().strip()
        if not url:
            self.output.append('Enter a base URL')
            return
        self.worker = WebScanWorker(url)
        self.worker.done.connect(self.on_done)
        self.worker.start()
        self.output.append('Scanning started...')

    def on_done(self, scanner: WebScanner):
        self.scanner = scanner
        enriched = enrich_findings(scanner.findings)
        for f in enriched:
            self.output.append(f"{f['type']}: {f['url']} - {f['detail']}")
            if f.get('mitre_technique'):
                self.output.append(f"  MITRE: {f['mitre_technique']}")
        text = '\n'.join([f"{f['type']} {f.get('mitre_technique','')} {f['url']} {f['detail']}" for f in enriched])
        ai = summarize('WebScan Report', text)
        if ai:
            self.output.append('\nAI Summary:\n' + ai)
        else:
            self.output.append('\nAI Summary unavailable (no key or error).')

    def export_html(self):
        if not self.scanner:
            self.output.append('Run a scan first.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export HTML', os.path.expanduser('~'), 'HTML (*.html)')
        if path:
            self.scanner.export_html(path)
            self.output.append(f'HTML saved to {path}')

    def export_pdf(self):
        if not self.scanner:
            self.output.append('Run a scan first.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export PDF', os.path.expanduser('~'), 'PDF (*.pdf)')
        if path:
            self.scanner.export_pdf(path)
            self.output.append(f'PDF saved to {path}')
