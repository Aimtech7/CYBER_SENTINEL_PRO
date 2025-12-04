import os
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTableWidget,
    QTableWidgetItem, QLineEdit, QComboBox, QTextEdit, QFileDialog, QSpinBox
)
from core.wifi.wifi_controller import scan_networks, list_interfaces, has_aircrack_tools
from core.wifi import aircrack


class StreamWorker(QThread):
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


class WifiTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.worker = None

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('WiFi Analyzer & Cracker')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        self.iface_combo = QComboBox()
        self.iface_combo.addItems(list_interfaces())
        top.addWidget(QLabel('Interface'))
        top.addWidget(self.iface_combo)
        scan_btn = QPushButton('Scan Networks')
        self.auto_btn = QPushButton('Auto Scan')
        scan_btn.clicked.connect(self.scan)
        self.auto_btn.setCheckable(True)
        self.auto_btn.toggled.connect(self.auto_scan_toggle)
        top.addWidget(scan_btn)
        top.addWidget(self.auto_btn)
        root.addLayout(top)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(['SSID', 'BSSID', 'Signal', 'Auth'])
        root.addWidget(self.table)

        controls = QHBoxLayout()
        self.mon_iface = QLineEdit()
        self.mon_iface.setPlaceholderText('Interface in monitor mode (e.g., wlan0mon)')
        controls.addWidget(self.mon_iface)
        self.bssid_edit = QLineEdit(); self.bssid_edit.setPlaceholderText('Target BSSID')
        controls.addWidget(self.bssid_edit)
        self.channel_spin = QSpinBox(); self.channel_spin.setRange(1, 165); self.channel_spin.setValue(6)
        controls.addWidget(QLabel('Channel'))
        controls.addWidget(self.channel_spin)
        root.addLayout(controls)

        actions = QHBoxLayout()
        self.start_mon_btn = QPushButton('Start Monitor')
        self.stop_mon_btn = QPushButton('Stop Monitor')
        self.cap_btn = QPushButton('Capture Handshake')
        self.deauth_btn = QPushButton('Deauth Attack')
        self.crack_btn = QPushButton('Crack (wordlist)')
        self.auto_crack_btn = QPushButton('Auto Crack Handshake')
        actions.addWidget(self.start_mon_btn)
        actions.addWidget(self.stop_mon_btn)
        actions.addWidget(self.cap_btn)
        actions.addWidget(self.deauth_btn)
        actions.addWidget(self.crack_btn)
        actions.addWidget(self.auto_crack_btn)
        root.addLayout(actions)

        self.output = QTextEdit(); self.output.setReadOnly(True); self.output.setPlaceholderText('Live terminal output...')
        root.addWidget(self.output)

        self.cap_path = None
        self.wordlist_path = None
        cap_select = QPushButton('Select capture output file')
        wl_select = QPushButton('Select wordlist')
        bottom = QHBoxLayout()
        bottom.addWidget(cap_select)
        bottom.addWidget(wl_select)
        root.addLayout(bottom)

        cap_select.clicked.connect(self.select_cap)
        wl_select.clicked.connect(self.select_wl)
        self.start_mon_btn.clicked.connect(self.start_monitor)
        self.stop_mon_btn.clicked.connect(self.stop_monitor)
        self.cap_btn.clicked.connect(self.capture)
        self.deauth_btn.clicked.connect(self.deauth)
        self.crack_btn.clicked.connect(self.crack)
        self.auto_crack_btn.clicked.connect(self.auto_crack)

        if not has_aircrack_tools():
            self.output.append('Aircrack-ng tools not detected. Advanced features require Linux/WSL with aircrack-ng.')

    def log(self, s: str):
        self.output.append(s)

    def scan(self):
        iface = self.iface_combo.currentText() if self.iface_combo.count() else None
        nets = scan_networks(iface)
        self.table.setRowCount(0)
        for n in nets:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(n.get('ssid') or ''))
            self.table.setItem(r, 1, QTableWidgetItem(n.get('bssid') or ''))
            self.table.setItem(r, 2, QTableWidgetItem(str(n.get('signal'))))
            self.table.setItem(r, 3, QTableWidgetItem(str(n.get('auth'))))

    def auto_scan_toggle(self, on: bool):
        if on:
            self.output.append('Auto scanning started')
            self.auto_thread = AutoScanWorker(self.iface_combo.currentText())
            self.auto_thread.result.connect(self.update_scan_results)
            self.auto_thread.start()
        else:
            try:
                self.auto_thread.stop()
            except Exception:
                pass
            self.output.append('Auto scanning stopped')

    def update_scan_results(self, nets):
        self.table.setRowCount(0)
        for n in nets:
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(n.get('ssid') or ''))
            self.table.setItem(r, 1, QTableWidgetItem(n.get('bssid') or ''))
            self.table.setItem(r, 2, QTableWidgetItem(str(n.get('signal'))))
            self.table.setItem(r, 3, QTableWidgetItem(str(n.get('auth'))))

    def select_cap(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Select capture output', os.path.expanduser('~'), 'Cap (*.cap);;Pcap (*.pcap)')
        if path:
            self.cap_path = path
            self.log(f'Capture file: {path}')

    def select_wl(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Select wordlist', os.path.expanduser('~'), 'Text (*.txt);;All (*)')
        if path:
            self.wordlist_path = path
            self.log(f'Wordlist: {path}')

    def _start_worker(self, fn, *args, **kwargs):
        if self.worker and self.worker.isRunning():
            self.log('Another task is running. Please wait.')
            return
        self.worker = StreamWorker(fn, *args, **kwargs)
        self.worker.line.connect(self.log)
        self.worker.done.connect(lambda code: self.log(f'Process exited with code {code}'))
        self.worker.start()

    def start_monitor(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.log('No interface selected.')
            return
        self._start_worker(aircrack.start_monitor, iface)

    def stop_monitor(self):
        iface = self.iface_combo.currentText()
        if not iface:
            self.log('No interface selected.')
            return
        self._start_worker(aircrack.stop_monitor, iface)

    def capture(self):
        mon = self.mon_iface.text().strip()
        bssid = self.bssid_edit.text().strip()
        ch = self.channel_spin.value()
        if not (mon and bssid and self.cap_path):
            self.log('Monitor iface, BSSID, and capture output are required.')
            return
        self._start_worker(aircrack.capture_handshake, mon, bssid, ch, self.cap_path)

    def deauth(self):
        mon = self.mon_iface.text().strip()
        bssid = self.bssid_edit.text().strip()
        if not (mon and bssid):
            self.log('Monitor iface and BSSID are required.')
            return
        self._start_worker(aircrack.deauth_attack, mon, bssid, None, 10)

    def crack(self):
        if not (self.cap_path and self.wordlist_path):
            self.log('Select capture file and wordlist.')
            return
        self._start_worker(aircrack.crack_handshake, self.cap_path, self.wordlist_path)

    def auto_crack(self):
        mon = self.mon_iface.text().strip()
        bssid = self.bssid_edit.text().strip()
        ch = self.channel_spin.value()
        if not (mon and bssid and self.wordlist_path and self.cap_path):
            self.log('Monitor iface, BSSID, channel, capture output, and wordlist are required.')
            return
        self.worker = AutoCrackWorker(mon, bssid, ch, self.cap_path, self.wordlist_path)
        self.worker.line.connect(self.log)
        self.worker.done.connect(lambda c: self.log(f'Auto crack finished {c}'))
        self.worker.start()

class AutoScanWorker(QThread):
    result = pyqtSignal(list)
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self._stop = False
    def run(self):
        while not self._stop:
            nets = scan_networks(self.iface)
            self.result.emit(nets)
            self.msleep(3000)
    def stop(self):
        self._stop = True

class AutoCrackWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal(int)
    def __init__(self, mon, bssid, ch, cap_path, wordlist):
        super().__init__()
        self.mon = mon
        self.bssid = bssid
        self.ch = ch
        self.cap_path = cap_path
        self.wordlist = wordlist
    def run(self):
        def emit(s):
            self.line.emit(s)
        aircrack.deauth_attack(self.mon, self.bssid, None, 10, on_line=emit)
        aircrack.capture_handshake_timeout(self.mon, self.bssid, self.ch, self.cap_path, 30, on_line=emit)
        code = aircrack.crack_handshake(self.cap_path, self.wordlist, on_line=emit)
        self.done.emit(code)
