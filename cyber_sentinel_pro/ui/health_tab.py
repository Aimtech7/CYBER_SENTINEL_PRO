import psutil
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel
import pyqtgraph as pg
from core.utils.ai_client import summarize


class HealthWorker(QThread):
    metrics = pyqtSignal(dict)
    def run(self):
        while True:
            m = {
                'cpu': psutil.cpu_percent(interval=0.5),
                'ram': psutil.virtual_memory().percent,
                'disk': psutil.disk_usage('/').percent,
                'net': psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv,
            }
            self.metrics.emit(m)


class HealthTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('System Health Dashboard')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)
        self.plot = pg.PlotWidget(); self.plot.setBackground('#0f1320')
        root.addWidget(self.plot)
        self.curves = {
            'cpu': self.plot.plot(pen=pg.mkPen('#4db5ff', width=2)),
            'ram': self.plot.plot(pen=pg.mkPen('#7cffc4', width=2)),
            'disk': self.plot.plot(pen=pg.mkPen('#ffcd4d', width=2)),
        }
        self.series = {k: [] for k in self.curves}
        self.ai = QLabel(''); root.addWidget(self.ai)
        self.worker = HealthWorker(); self.worker.metrics.connect(self.update)
        self.worker.start()

    def update(self, m: dict):
        for k in ('cpu', 'ram', 'disk'):
            s = self.series[k]
            s.append(m[k])
            if len(s) > 200:
                s.pop(0)
            self.curves[k].setData(list(range(len(s))), s)
        txt = f"CPU {m['cpu']}% RAM {m['ram']}% Disk {m['disk']}%"
        ai = summarize('Health', txt)
        if ai:
            self.ai.setText(ai)
