from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QFileDialog
)
import pyqtgraph as pg
from PyQt6.QtCore import QThread, pyqtSignal
from core.nmap.nmap_client import NmapClient


class NmapWorker(QThread):
    done = pyqtSignal(object)
    def __init__(self, target: str, profile: str):
        super().__init__()
        self.target = target
        self.profile = profile
    def run(self):
        client = NmapClient()
        res = client.scan(self.target, self.profile)
        self.done.emit(res)


class NmapTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.res = None

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Network Mapper (Nmap)')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        self.target_edit = QLineEdit(); self.target_edit.setPlaceholderText('192.168.1.0/24 or domain')
        self.profile_combo = QComboBox(); self.profile_combo.addItems(['quick', 'intense', 'full'])
        start_btn = QPushButton('Run')
        export_btn = QPushButton('Export CSV')
        top.addWidget(self.target_edit)
        top.addWidget(self.profile_combo)
        top.addWidget(start_btn)
        top.addWidget(export_btn)
        root.addLayout(top)

        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(['Host', 'Port', 'State', 'Name', 'Product', 'Version'])
        root.addWidget(self.table)

        self.chart = pg.PlotWidget()
        self.chart.setBackground('#0f1320')
        root.addWidget(self.chart)

        start_btn.clicked.connect(self.run_scan)
        export_btn.clicked.connect(self.export_csv)

    def run_scan(self):
        t = self.target_edit.text().strip()
        p = self.profile_combo.currentText()
        if not t:
            return
        self.worker = NmapWorker(t, p)
        self.worker.done.connect(self.on_done)
        self.worker.start()

    def on_done(self, res):
        self.res = res
        client = NmapClient()
        rows = client.parse(res)
        self.table.setRowCount(0)
        port_counts = {}
        for r in rows:
            i = self.table.rowCount(); self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(r['host']))
            self.table.setItem(i, 1, QTableWidgetItem(str(r['port'])))
            self.table.setItem(i, 2, QTableWidgetItem(r['state']))
            self.table.setItem(i, 3, QTableWidgetItem(r.get('name') or ''))
            self.table.setItem(i, 4, QTableWidgetItem(r.get('product') or ''))
            self.table.setItem(i, 5, QTableWidgetItem(r.get('version') or ''))
            port_counts[r['port']] = port_counts.get(r['port'], 0) + 1
        xs = list(port_counts.keys())
        ys = list(port_counts.values())
        self.chart.clear()
        bg = pg.BarGraphItem(x=xs, height=ys, width=0.8, brush=pg.mkBrush('#4db5ff'))
        self.chart.addItem(bg)

    def export_csv(self):
        if not self.res:
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export CSV', '', 'CSV (*.csv)')
        if not path:
            return
        client = NmapClient()
        rows = client.parse(self.res)
        import csv
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh)
            w.writerow(['Host', 'Port', 'State', 'Name', 'Product', 'Version'])
            for r in rows:
                w.writerow([r['host'], r['port'], r['state'], r.get('name',''), r.get('product',''), r.get('version','')])

