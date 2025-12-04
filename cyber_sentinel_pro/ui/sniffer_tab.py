import os
import binascii
from collections import deque
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QComboBox, QTextEdit, QFileDialog
)
import pyqtgraph as pg
import psutil
from core.sniffer.sniffer import Sniffer, Captured
from core.wifi.wifi_controller import has_aircrack_tools
from core.wifi import aircrack


class SnifferWorker(QThread):
    packet = pyqtSignal(object)
    finished = pyqtSignal()

    def __init__(self, iface: str, bpf: str):
        super().__init__()
        self.iface = iface
        self.bpf = bpf
        self._stop = False
        self.sniffer = Sniffer(iface=iface, bpf=bpf)

    def run(self):
        self.sniffer.start(on_packet=lambda cap: self.packet.emit(cap), stop_flag=lambda: self._stop)
        self.finished.emit()

    def stop(self):
        self._stop = True


class ACWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal(int)
    def __init__(self, fn, *args, **kwargs):
        super().__init__()
        self.fn = fn
        self.args = args
        self.kwargs = kwargs
    def run(self):
        def on_line(s):
            self.line.emit(s)
        code = self.fn(*self.args, on_line=on_line, **self.kwargs)
        self.done.emit(code)


class SnifferTab(QWidget):
    def __init__(self):
        super().__init__()
        self.worker = None
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Packet Sniffer Dashboard')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)
        self.status_label = QLabel('')
        root.addWidget(self.status_label)

        top = QHBoxLayout()
        self.iface_edit = QComboBox()
        self.iface_edit.setEditable(True)
        self.iface_edit.setPlaceholderText('Interface (e.g., Ethernet, Wi-Fi)')
        try:
            self.iface_edit.addItems(list(psutil.net_if_addrs().keys()))
        except Exception:
            pass
        top.addWidget(self.iface_edit)
        self.filter_edit = QComboBox()
        self.filter_edit.setEditable(True)
        self.filter_edit.addItems(['', 'tcp', 'udp', 'arp', 'port 80', 'port 53'])
        top.addWidget(self.filter_edit)
        start_btn = QPushButton('Start Capture')
        stop_btn = QPushButton('Stop Capture')
        export_btn = QPushButton('Export PCAP')
        import_btn = QPushButton('Import PCAP')
        top.addWidget(start_btn)
        top.addWidget(stop_btn)
        top.addWidget(export_btn)
        top.addWidget(import_btn)
        root.addLayout(top)

        ac_row = QHBoxLayout()
        self.mon_start_btn = QPushButton('Start Monitor')
        self.mon_stop_btn = QPushButton('Stop Monitor')
        ac_row.addWidget(self.mon_start_btn)
        ac_row.addWidget(self.mon_stop_btn)
        root.addLayout(ac_row)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(['Time', 'Proto', 'Src', 'Dst', 'Len'])
        root.addWidget(self.table)

        bottom = QHBoxLayout()
        self.hex_view = QTextEdit(); self.hex_view.setReadOnly(True)
        self.ascii_view = QTextEdit(); self.ascii_view.setReadOnly(True)
        bottom.addWidget(self.hex_view)
        bottom.addWidget(self.ascii_view)
        root.addLayout(bottom)

        self.plot = pg.PlotWidget()
        self.plot.setBackground('#0f1320')
        self.plot.showGrid(x=True, y=True, alpha=0.3)
        self.curve = self.plot.plot(pen=pg.mkPen('#4db5ff', width=2))
        root.addWidget(self.plot)
        self.rate_buf = deque(maxlen=100)
        self.rate_x = deque(maxlen=100)
        self.ticks = 0

        start_btn.clicked.connect(self.start)
        stop_btn.clicked.connect(self.stop)
        export_btn.clicked.connect(self.export)
        import_btn.clicked.connect(self.import_pcap)
        self.table.cellClicked.connect(self.show_packet)
        self.mon_start_btn.clicked.connect(self.start_monitor)
        self.mon_stop_btn.clicked.connect(self.stop_monitor)
        if not has_aircrack_tools():
            self.mon_start_btn.setEnabled(False)
            self.mon_stop_btn.setEnabled(False)

    def start(self):
        iface = self.iface_edit.currentText().strip()
        bpf = self.filter_edit.currentText().strip()
        if not iface:
            self._status('Enter an interface name.')
            return
        self.worker = SnifferWorker(iface, bpf)
        self.worker.packet.connect(self.on_packet)
        self.worker.finished.connect(lambda: self._status('Capture stopped'))
        self.worker.start()
        self._status('Capture started')

    def stop(self):
        if self.worker:
            self.worker.stop()

    def export(self):
        if not self.worker:
            self._status('No capture session')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export PCAP', os.path.expanduser('~'), 'PCAP (*.pcap)')
        if path:
            try:
                self.worker.sniffer.export_pcap(path)
                self._status(f'Exported to {path}')
            except Exception as e:
                self._status(f'Export failed: {e}')

    def import_pcap(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Import PCAP', os.path.expanduser('~'), 'PCAP (*.pcap *.pcapng);;All (*)')
        if not path:
            return
        try:
            if not self.worker:
                # create a sniffer instance with no live capture
                self.worker = SnifferWorker(self.iface_edit.currentText().strip(), self.filter_edit.currentText().strip())
            self.worker.sniffer.import_pcap(path)
            self._status(f'Imported {path}')
            # refresh table from stats
            for cap in self.worker.sniffer.stats():
                r = self.table.rowCount(); self.table.insertRow(r)
                self.table.setItem(r, 0, QTableWidgetItem(f"{cap.ts:.2f}"))
                self.table.setItem(r, 1, QTableWidgetItem(cap.proto))
                self.table.setItem(r, 2, QTableWidgetItem(cap.src))
                self.table.setItem(r, 3, QTableWidgetItem(cap.dst))
                self.table.setItem(r, 4, QTableWidgetItem(str(cap.length)))
        except Exception as e:
            self._status(f'Import failed: {e}')

    def start_monitor(self):
        iface = self.iface_edit.currentText().strip()
        if not iface:
            self._status('Enter an interface name.')
            return
        w = ACWorker(aircrack.start_monitor, iface)
        w.line.connect(lambda s: self._status(s))
        w.done.connect(lambda c: self._status(f'Monitor start exited {c}'))
        w.start()

    def stop_monitor(self):
        iface = self.iface_edit.currentText().strip()
        if not iface:
            self._status('Enter an interface name.')
            return
        w = ACWorker(aircrack.stop_monitor, iface)
        w.line.connect(lambda s: self._status(s))
        w.done.connect(lambda c: self._status(f'Monitor stop exited {c}'))
        w.start()

    def on_packet(self, cap: Captured):
        r = self.table.rowCount(); self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(f"{cap.ts:.2f}"))
        self.table.setItem(r, 1, QTableWidgetItem(cap.proto))
        self.table.setItem(r, 2, QTableWidgetItem(cap.src))
        self.table.setItem(r, 3, QTableWidgetItem(cap.dst))
        self.table.setItem(r, 4, QTableWidgetItem(str(cap.length)))
        self.rate_buf.append(self.rate_buf[-1] + 1 if self.rate_buf else 1)
        self.ticks += 1
        self.rate_x.append(self.ticks)
        self.curve.setData(list(self.rate_x), list(self.rate_buf))

    def show_packet(self, row: int, col: int):
        try:
            ts = float(self.table.item(row, 0).text())
        except Exception:
            return
        # Find matching record by timestamp
        recs = self.worker.sniffer.stats()
        for r in recs:
            if abs(r.ts - ts) < 1e-2:
                raw = r.raw
                self.hex_view.setText(binascii.hexlify(raw).decode())
                try:
                    self.ascii_view.setText(raw.decode(errors='ignore'))
                except Exception:
                    self.ascii_view.setText('')
                break

    def _status(self, s: str):
        self.status_label.setText(s)
