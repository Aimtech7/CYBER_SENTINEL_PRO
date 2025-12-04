from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QHBoxLayout
from apscheduler.schedulers.background import BackgroundScheduler
import subprocess


class SchedulerTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.scheduler = BackgroundScheduler()
        self.scheduler.start()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Scheduler')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        row = QHBoxLayout()
        self.host = QLineEdit(); self.host.setPlaceholderText('Host for scheduled ping')
        self.minutes = QLineEdit(); self.minutes.setPlaceholderText('Interval minutes (e.g., 15)')
        add_btn = QPushButton('Add Ping Job')
        row.addWidget(self.host)
        row.addWidget(self.minutes)
        row.addWidget(add_btn)
        root.addLayout(row)

        self.log = QTextEdit(); self.log.setReadOnly(True)
        root.addWidget(self.log)

        add_btn.clicked.connect(self.add_job)

    def add_job(self):
        host = (self.host.text() or '').strip()
        try:
            minutes = int((self.minutes.text() or '15').strip())
        except Exception:
            minutes = 15
        if not host:
            self.log.append('Enter a host.')
            return
        def task():
            try:
                proc = subprocess.run(['ping', '-n', '2', host], capture_output=True, text=True)
                self.log.append(f"Ping {host}:\n" + (proc.stdout or proc.stderr))
            except Exception as e:
                self.log.append(f'Ping error: {e}')
        self.scheduler.add_job(task, 'interval', minutes=minutes, id=f'ping:{host}', replace_existing=True)
        self.log.append(f'Added job ping:{host} every {minutes} min')
