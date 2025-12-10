from PyQt6.QtCore import QThread, pyqtSignal, QTimer
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QCheckBox, QLineEdit, QMessageBox, QFileDialog
import json
import time
import json
from core.automation.engine import AutomationEngine
from core.utils.secure_storage import load_setting, save_setting


class AutomationTab(QWidget):
    def __init__(self):
        super().__init__()
        self.engine = AutomationEngine()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('Automation Engine')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)

        self.tasks = {
            'siem': self._task_row('SIEM Monitor'),
            'iprep': self._task_row('IP Reputation'),
            'suspip': self._task_row('Suspicious IP Detector'),
            'fim': self._task_row('File Integrity Monitor'),
            'sandbox': self._task_row('Auto Sandbox'),
            'risk': self._task_row('AI Risk Scoring'),
            'notify': self._task_row('Notifier'),
        }
        for k, row in self.tasks.items():
            root.addLayout(row['layout'])

        settings_row = QHBoxLayout()
        self.task_sel = QLineEdit(); self.task_sel.setPlaceholderText('Task key (siem, iprep, suspip, fim, sandbox, risk, notify)')
        self.cfg = QTextEdit(); self.cfg.setPlaceholderText('{ }')
        save_btn = QPushButton('Save Settings')
        export_btn = QPushButton('Export Logs')
        settings_row.addWidget(self.task_sel)
        settings_row.addWidget(save_btn)
        settings_row.addWidget(export_btn)
        root.addLayout(settings_row)
        root.addWidget(self.cfg)

        self.logs = QTextEdit(); self.logs.setReadOnly(True)
        root.addWidget(self.logs)

        cfg_row = QHBoxLayout()
        self.task_sel = QLineEdit(); self.task_sel.setPlaceholderText('Task key (siem, iprep, suspip, fim, sandbox, risk, notify)')
        self.cfg = QTextEdit(); self.cfg.setPlaceholderText('{"interval":5}')
        save_cfg = QPushButton('Save Settings')
        cfg_row.addWidget(self.task_sel)
        cfg_row.addWidget(save_cfg)
        root.addLayout(cfg_row)
        root.addWidget(self.cfg)
        save_cfg.clicked.connect(self.save_settings)

        self.timer = QTimer(self)
        self.timer.setInterval(1200)
        self.timer.timeout.connect(self.refresh_logs)
        self.timer.start()

        save_btn.clicked.connect(self.save_settings)
        export_btn.clicked.connect(self.export_logs)

    def _task_row(self, name: str):
        h = QHBoxLayout()
        lbl = QLabel(name)
        start = QPushButton('Start')
        stop = QPushButton('Stop')
        status = QLabel('Stopped')
        last = QLabel('Last: -')
        h.addWidget(lbl)
        h.addWidget(start)
        h.addWidget(stop)
        h.addWidget(status)
        h.addWidget(last)
        start.clicked.connect(lambda _, n=name: self._start(n))
        stop.clicked.connect(lambda _, n=name: self._stop(n))
        return {'layout': h, 'status': status, 'last': last, 'start': start, 'stop': stop, 'name': name}

    def _key_from_name(self, name: str) -> str:
        for k, v in self.tasks.items():
            if v['name'] == name:
                return k
        return ''

    def _start(self, name: str):
        k = self._key_from_name(name)
        self.engine.start(k)
        self.tasks[k]['status'].setText('Running')

    def _stop(self, name: str):
        k = self._key_from_name(name)
        self.engine.stop(k)
        self.tasks[k]['status'].setText('Stopped')

    def refresh_logs(self):
        for k in self.tasks.keys():
            logs = self.engine.logs(k)
            try:
                lr = self.engine.tasks[k].last_run
                if lr:
                    self.tasks[k]['last'].setText('Last: ' + time.strftime('%H:%M:%S', time.localtime(lr)))
            except Exception:
                pass
            if logs:
                for s in logs:
                    color = '#ff7676' if ('Error' in s or 'Anomalies' in s) else '#4db5ff'
                    self.logs.append(f"<span style='color:{color}'>{k}: {s}</span>")

    def save_settings(self):
        key = self.task_sel.text().strip()
        if not key:
            return
        try:
            data = json.loads(self.cfg.toPlainText() or '{}')
        except Exception:
            QMessageBox.warning(self, 'Invalid JSON', 'Settings must be valid JSON')
            return
        try:
            t = self.engine.tasks.get(key)
            if not t:
                QMessageBox.warning(self, 'Unknown Task', f'No task "{key}"')
                return
            t.update_settings(data)
            QMessageBox.information(self, 'Saved', f'Settings saved for {key}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', str(e))

    def export_logs(self):
        key = self.task_sel.text().strip()
        if not key:
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export Logs', '', 'CSV (*.csv)')
        if not path:
            return
        ok = self.engine.export_logs(key, path)
        if ok:
            QMessageBox.information(self, 'Exported', f'Logs exported for {key}')
        else:
            QMessageBox.warning(self, 'Error', 'Failed to export logs')

    def save_settings(self):
        key = self.task_sel.text().strip()
        if not key:
            return
        try:
            data = json.loads(self.cfg.toPlainText() or '{}')
        except Exception:
            QMessageBox.warning(self, 'Invalid JSON', 'Settings must be valid JSON')
            return
        try:
            t = self.engine.tasks.get(key)
            if not t:
                QMessageBox.warning(self, 'Unknown Task', f'No task "{key}"')
                return
            t.update_settings(data)
            QMessageBox.information(self, 'Saved', f'Settings saved for {key}')
        except Exception as e:
            QMessageBox.warning(self, 'Error', str(e))
