import psutil
import time
from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QPushButton, QLineEdit, QMessageBox
from core.utils.secure_storage import load_setting, append_audit


class SystemPropertiesTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('System Properties')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)
        controls = QHBoxLayout()
        self.pid_edit = QLineEdit(); self.pid_edit.setPlaceholderText('PID')
        refresh_btn = QPushButton('Refresh')
        kill_btn = QPushButton('Terminate')
        suspend_btn = QPushButton('Suspend')
        resume_btn = QPushButton('Resume')
        controls.addWidget(self.pid_edit)
        controls.addWidget(refresh_btn)
        controls.addWidget(kill_btn)
        controls.addWidget(suspend_btn)
        controls.addWidget(resume_btn)
        root.addLayout(controls)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(['PID', 'Name', 'CPU %', 'Mem %', 'Threads', 'Status', 'User'])
        root.addWidget(self.table)
        refresh_btn.clicked.connect(self.refresh)
        kill_btn.clicked.connect(self.terminate)
        suspend_btn.clicked.connect(self.suspend)
        resume_btn.clicked.connect(self.resume)
        self.timer = QTimer(self)
        self.timer.setInterval(2000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()
        self.refresh()

    def refresh(self):
        self.table.setRowCount(0)
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'status', 'username']):
            r = self.table.rowCount(); self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(str(p.info.get('pid'))))
            self.table.setItem(r, 1, QTableWidgetItem(str(p.info.get('name'))))
            self.table.setItem(r, 2, QTableWidgetItem(f"{p.info.get('cpu_percent'):.1f}"))
            self.table.setItem(r, 3, QTableWidgetItem(f"{p.info.get('memory_percent'):.1f}"))
            self.table.setItem(r, 4, QTableWidgetItem(str(p.info.get('num_threads'))))
            self.table.setItem(r, 5, QTableWidgetItem(str(p.info.get('status'))))
            self.table.setItem(r, 6, QTableWidgetItem(str(p.info.get('username') or '')))

    def _pid(self):
        try:
            return int(self.pid_edit.text().strip())
        except Exception:
            return None

    def terminate(self):
        pid = self._pid()
        if not pid:
            return
        if load_setting('safe_mode', True):
            QMessageBox.warning(self, 'Restricted', 'Safe Mode enabled')
            return
        if (load_setting('role', 'admin') or '').lower() != 'admin':
            QMessageBox.warning(self, 'Restricted', 'Admin role required')
            return
        ok = QMessageBox.question(self, 'Confirm', f'Terminate PID {pid}?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            psutil.Process(pid).terminate()
            append_audit({'ts': time.time(), 'action': 'terminate', 'pid': pid})
        except Exception:
            pass

    def suspend(self):
        pid = self._pid()
        if not pid:
            return
        if load_setting('safe_mode', True):
            QMessageBox.warning(self, 'Restricted', 'Safe Mode enabled')
            return
        if (load_setting('role', 'admin') or '').lower() != 'admin':
            QMessageBox.warning(self, 'Restricted', 'Admin role required')
            return
        ok = QMessageBox.question(self, 'Confirm', f'Suspend PID {pid}?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            psutil.Process(pid).suspend()
            append_audit({'ts': time.time(), 'action': 'suspend', 'pid': pid})
        except Exception:
            pass

    def resume(self):
        pid = self._pid()
        if not pid:
            return
        if load_setting('safe_mode', True):
            QMessageBox.warning(self, 'Restricted', 'Safe Mode enabled')
            return
        if (load_setting('role', 'admin') or '').lower() != 'admin':
            QMessageBox.warning(self, 'Restricted', 'Admin role required')
            return
        ok = QMessageBox.question(self, 'Confirm', f'Resume PID {pid}?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            psutil.Process(pid).resume()
            append_audit({'ts': time.time(), 'action': 'resume', 'pid': pid})
        except Exception:
            pass
