import os
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog, QTableWidget, QTableWidgetItem
import pyqtgraph as pg
from core.ids.suricata_parser import parse_eve_json


class IDSTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.data = None

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('IDS (Suricata) Log Viewer')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        open_btn = QPushButton('Open eve.json')
        analyze_btn = QPushButton('Analyze')
        top.addWidget(open_btn)
        top.addWidget(analyze_btn)
        root.addLayout(top)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['Time', 'Severity', 'Signature', 'Src', 'Dst'])
        root.addWidget(self.table)
        self.chart = pg.PlotWidget(); self.chart.setBackground('#0f1320')
        root.addWidget(self.chart)
        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)

        open_btn.clicked.connect(self.open)
        analyze_btn.clicked.connect(self.analyze)

    def open(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Open eve.json', os.path.expanduser('~'), 'JSON (*.json);;All (*)')
        if path:
            with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                lines = fh.read().splitlines()
            self.data = parse_eve_json(lines)
            self.output.append(f'Loaded {len(self.data["alerts"]) } alerts')
            self.fill_table()

    def fill_table(self):
        if not self.data:
            return
        self.table.setRowCount(0)
        for a in self.data['alerts']:
            i = self.table.rowCount(); self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(a.get('timestamp') or ''))
            self.table.setItem(i, 1, QTableWidgetItem(str(a.get('severity'))))
            self.table.setItem(i, 2, QTableWidgetItem(a.get('signature') or ''))
            self.table.setItem(i, 3, QTableWidgetItem(a.get('src_ip') or ''))
            self.table.setItem(i, 4, QTableWidgetItem(a.get('dest_ip') or ''))

    def analyze(self):
        if not self.data:
            return
        sev = self.data['sev_counts']
        xs = list(sev.keys())
        ys = list(sev.values())
        self.chart.clear()
        bg = pg.BarGraphItem(x=xs, height=ys, width=0.8, brush=pg.mkBrush('#4db5ff'))
        self.chart.addItem(bg)
        self.output.append('Top signatures: ' + str(sorted(self.data['sig_counts'].items(), key=lambda x: -x[1])[:5]))

