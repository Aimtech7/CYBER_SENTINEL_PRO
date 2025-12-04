import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog, QTableWidget, QTableWidgetItem, QLineEdit
)
import pyqtgraph as pg
from core.siem.analyzer import parse_lines
from core.utils.ai_client import summarize
from core.utils.attack_map import enrich_findings


class SIEMTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.lines = []

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('SIEM Log Analyzer')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        load_btn = QPushButton('Load Logs')
        analyze_btn = QPushButton('Analyze')
        self.search_edit = QLineEdit(); self.search_edit.setPlaceholderText('Search pattern (regex)')
        search_btn = QPushButton('Search & Highlight')
        top.addWidget(load_btn)
        top.addWidget(analyze_btn)
        top.addWidget(self.search_edit)
        top.addWidget(search_btn)
        root.addLayout(top)

        self.table = QTableWidget(0, 2)
        self.table.setHorizontalHeaderLabels(['Type', 'Detail'])
        root.addWidget(self.table)

        self.chart = pg.PlotWidget(); self.chart.setBackground('#0f1320')
        root.addWidget(self.chart)

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)
        self.log_view = QTextEdit(); self.log_view.setReadOnly(True)
        root.addWidget(self.log_view)

        load_btn.clicked.connect(self.load)
        analyze_btn.clicked.connect(self.analyze)
        search_btn.clicked.connect(self.search)

    def load(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open Log File', os.path.expanduser('~'), 'Text (*.log *.txt);;All (*)')
        if path:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                self.lines = fh.read().splitlines()
            self.output.append(f'Loaded {len(self.lines)} lines from {path}')

    def analyze(self):
        if not self.lines:
            self.output.append('Load a log file first.')
            return
        res = parse_lines(self.lines)
        self.table.setRowCount(0)
        enriched = enrich_findings(res['findings'])
        for f in enriched:
            i = self.table.rowCount(); self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(f['type']))
            self.table.setItem(i, 1, QTableWidgetItem(f['detail']))
            if f.get('mitre_technique'):
                self.output.append(f"MITRE: {f['mitre_technique']} - {f['detail']}")
        xs = [int(k) for k in res['status_counts'].keys()]
        ys = list(res['status_counts'].values())
        self.chart.clear()
        bg = pg.BarGraphItem(x=xs, height=ys, width=5, brush=pg.mkBrush('#4db5ff'))
        self.chart.addItem(bg)
        text = f"Auth failures: {res['auth_failures']}\nTop URIs: {res['top_uris']}\nFindings: {enriched}"
        ai = summarize('SIEM Analysis', text)
        if ai:
            self.output.append('AI Summary:\n' + ai)
        else:
            self.output.append('AI Summary unavailable.')

    def search(self):
        pat = self.search_edit.text().strip()
        if not pat:
            return
        import re
        try:
            rgx = re.compile(pat, re.IGNORECASE)
        except Exception as e:
            self.output.append(f'Invalid regex: {e}')
            return
        matches = [ln for ln in self.lines if rgx.search(ln)]
        html = ''
        for ln in matches:
            hl = rgx.sub(lambda m: f"<span style='background:#132041;color:#9bd1ff'>{m.group(0)}</span>", ln)
            html += hl + '<br>'
        self.log_view.setHtml(html or 'No matches')
