import psutil
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem, QHBoxLayout, QTextEdit, QProgressBar
from core.utils.secure_storage import load_setting, save_setting


class EndpointTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Endpoint Forensics')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        btns = QHBoxLayout()
        refresh_btn = QPushButton('Refresh Processes')
        save_base_btn = QPushButton('Save Baseline')
        compare_btn = QPushButton('Compare Baseline')
        btns.addWidget(refresh_btn)
        btns.addWidget(save_base_btn)
        btns.addWidget(compare_btn)
        root.addLayout(btns)

        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(['PID', 'Name', 'CPU %', 'Memory %'])
        root.addWidget(self.table)

        self.log_view = QTextEdit(); self.log_view.setReadOnly(True)
        root.addWidget(self.log_view)

        self.loader = QProgressBar(); self.loader.setRange(0,0); self.loader.hide()
        root.addWidget(self.loader)

        refresh_btn.clicked.connect(self.refresh)
        save_base_btn.clicked.connect(self.save_baseline)
        compare_btn.clicked.connect(self.compare_baseline)

        self.refresh()

    def refresh(self):
        self.loader.show(); self.table.setRowCount(0)
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            i = self.table.rowCount(); self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(str(p.info.get('pid'))))
            self.table.setItem(i, 1, QTableWidgetItem(p.info.get('name') or ''))
            self.table.setItem(i, 2, QTableWidgetItem(str(p.info.get('cpu_percent'))))
            self.table.setItem(i, 3, QTableWidgetItem(f"{(p.info.get('memory_percent') or 0):.2f}"))
        self.loader.hide()

    def save_baseline(self):
        names = []
        for r in range(self.table.rowCount()):
            nm = self.table.item(r, 1).text()
            names.append(nm)
        save_setting('endpoint_baseline', names)

    def compare_baseline(self):
        baseline = load_setting('endpoint_baseline', []) or []
        current = []
        for r in range(self.table.rowCount()):
            current.append(self.table.item(r, 1).text())
        new = [n for n in current if n not in baseline]
        missing = [n for n in baseline if n not in current]
        # Mark new processes at top
        self.table.setRowCount(0)
        for nm in new:
            i = self.table.rowCount(); self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(''))
            it = QTableWidgetItem(nm + ' (NEW)'); self.table.setItem(i, 1, it)
            self.table.setItem(i, 2, QTableWidgetItem(''))
            self.table.setItem(i, 3, QTableWidgetItem(''))
            self.log_view.append("<span style='color:#e0a800'>[WARNING] New process: " + nm + "</span>")
        for nm in missing:
            i = self.table.rowCount(); self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(''))
            it = QTableWidgetItem(nm + ' (MISSING)'); self.table.setItem(i, 1, it)
            self.table.setItem(i, 2, QTableWidgetItem(''))
            self.table.setItem(i, 3, QTableWidgetItem(''))
            self.log_view.append("<span style='color:#9bd1ff'>[INFO] Missing from baseline: " + nm + "</span>")
