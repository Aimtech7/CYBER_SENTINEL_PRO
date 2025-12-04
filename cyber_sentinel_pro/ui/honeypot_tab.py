from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QLineEdit
from core.honeypot.honeypot import HoneypotManager


class HoneypotWorker(QThread):
    event = pyqtSignal(dict)
    def __init__(self, host: str, ports: list[int]):
        super().__init__()
        self.host = host
        self.ports = ports
        self.hp = HoneypotManager(host, ports)
        self._stop = False
    def run(self):
        self.hp.start(on_event=lambda e: self.event.emit(e))
        while not self._stop:
            self.msleep(500)
        self.hp.stop()
    def stop(self):
        self._stop = True


class HoneypotTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.worker = None

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Honeypot')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        self.host_edit = QLineEdit(); self.host_edit.setText('0.0.0.0')
        self.ports_edit = QLineEdit(); self.ports_edit.setText('8080,2222,2323,4455')
        start_btn = QPushButton('Start')
        stop_btn = QPushButton('Stop')
        top.addWidget(self.host_edit)
        top.addWidget(self.ports_edit)
        top.addWidget(start_btn)
        top.addWidget(stop_btn)
        root.addLayout(top)

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)

        start_btn.clicked.connect(self.start)
        stop_btn.clicked.connect(self.stop)

    def start(self):
        host = self.host_edit.text().strip() or '0.0.0.0'
        ports = [int(x.strip()) for x in self.ports_edit.text().split(',') if x.strip().isdigit()]
        self.worker = HoneypotWorker(host, ports)
        self.worker.event.connect(lambda e: self.output.append(str(e)))
        self.worker.start()
        self.output.append('Honeypot started')

    def stop(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait()
            self.output.append('Honeypot stopped')

