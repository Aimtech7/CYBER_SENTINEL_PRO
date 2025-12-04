import time
import psutil
import pyqtgraph as pg
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QGridLayout


class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('System Dashboard')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)
        grid = QGridLayout()
        root.addLayout(grid)
        self.plots = {}
        self.series = {}
        keys = [
            ('cpu', '#4db5ff'),
            ('ram', '#7cffc4'),
            ('disk', '#ffcd4d'),
            ('net_mbps', '#ff7676'),
            ('packets', '#a97cff'),
        ]
        for i, (k, color) in enumerate(keys):
            pw = pg.PlotWidget(); pw.setBackground('#0f1320')
            curve = pw.plot(pen=pg.mkPen(color, width=2))
            lbl = QLabel(k.upper()); lbl.setStyleSheet('color:#9bd1ff')
            v = QVBoxLayout(); v.addWidget(lbl); v.addWidget(pw)
            w = QWidget(); w.setLayout(v)
            grid.addWidget(w, i // 2, i % 2)
            self.plots[k] = curve
            self.series[k] = []
        self.last_net = psutil.net_io_counters()
        self.last_time = time.time()
        self.timer = QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.sample)
        self.timer.start()

    def sample(self):
        cpu = psutil.cpu_percent(interval=None)
        ram = psutil.virtual_memory().percent
        disk = psutil.disk_usage('/').percent
        now = time.time()
        cur = psutil.net_io_counters()
        dt = max(now - self.last_time, 1e-6)
        b = (cur.bytes_sent + cur.bytes_recv) - (self.last_net.bytes_sent + self.last_net.bytes_recv)
        mbps = (b * 8) / dt / 1_000_000
        pk = (cur.packets_sent + cur.packets_recv) - (self.last_net.packets_sent + self.last_net.packets_recv)
        self.last_net = cur
        self.last_time = now
        vals = {
            'cpu': cpu,
            'ram': ram,
            'disk': disk,
            'net_mbps': mbps,
            'packets': pk,
        }
        for k, v in vals.items():
            s = self.series[k]
            s.append(v)
            if len(s) > 200:
                s.pop(0)
            self.plots[k].setData(list(range(len(s))), s)
