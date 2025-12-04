from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox
)
import pyqtgraph as pg
from core.threatintel.apis import vt_ip, vt_domain, vt_url, vt_file, shodan_ip, abuseipdb_ip, otx_general
from core.utils.ai_client import summarize


class ThreatIntelTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Threat Intelligence Dashboard')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        self.input_edit = QLineEdit(); self.input_edit.setPlaceholderText('IP, domain, URL, or file hash')
        check_btn = QPushButton('Check')
        top.addWidget(self.input_edit)
        top.addWidget(check_btn)
        root.addLayout(top)

        actions = QHBoxLayout()
        self.block_btn = QPushButton('Block IP')
        self.unblock_btn = QPushButton('Unblock IP')
        actions.addWidget(self.block_btn)
        actions.addWidget(self.unblock_btn)
        root.addLayout(actions)

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)

        self.chart = pg.PlotWidget(); self.chart.setBackground('#0f1320')
        root.addWidget(self.chart)

        check_btn.clicked.connect(self.check)
        self.block_btn.clicked.connect(self.block_ip)
        self.unblock_btn.clicked.connect(self.unblock_ip)

    def check(self):
        val = self.input_edit.text().strip()
        if not val:
            return
        res = None
        score = 0
        if val.count('.') == 3 and all(x.isdigit() for x in val.split('.')):
            vt = vt_ip(val)
            sh = shodan_ip(val)
            ab = abuseipdb_ip(val)
            otx = otx_general('IPv4', val)
            res = {'virustotal': vt, 'shodan': sh, 'abuseipdb': ab, 'otx': otx}
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0
        elif val.startswith('http'):
            vt = vt_url(val)
            otx = otx_general('url', val)
            res = {'virustotal': vt, 'otx': otx}
            try:
                score = vt['data']['attributes']['stats']['malicious']
            except Exception:
                score = 0
        elif len(val) in (32, 40, 64):
            vt = vt_file(val)
            otx = otx_general('file', val)
            res = {'virustotal': vt, 'otx': otx}
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0
        else:
            vt = vt_domain(val)
            otx = otx_general('domain', val)
            res = {'virustotal': vt, 'otx': otx}
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0

        self.output.setText(str(res))
        self.chart.clear()
        bars = pg.BarGraphItem(x=[0, 1], height=[score, max(0, 100 - score)], width=0.8, brush=pg.mkBrush('#4db5ff'))
        self.chart.addItem(bars)
        text = str(res)
        ai = summarize('Threat Intel Summary', text)
        if ai:
            self.output.append('\nAI Summary:\n' + ai)

    def block_ip(self):
        val = self.input_edit.text().strip()
        parts = val.split('.')
        if not val or val.count('.') != 3 or not all(p.isdigit() for p in parts):
            return
        ok = QMessageBox.question(self, 'Confirm Block', f'AI recommends blocking {val}. Proceed?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.utils.firewall import block_ip, history
            res = block_ip(val)
            self.output.append('Block result: ' + str(res))
            self.output.append('History: ' + str(history()))
        except Exception as e:
            self.output.append('Block error: ' + str(e))

    def unblock_ip(self):
        val = self.input_edit.text().strip()
        parts = val.split('.')
        if not val or val.count('.') != 3 or not all(p.isdigit() for p in parts):
            return
        ok = QMessageBox.question(self, 'Confirm Unblock', f'Unblock {val}?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.utils.firewall import unblock_ip, history
            res = unblock_ip(val)
            self.output.append('Unblock result: ' + str(res))
            self.output.append('History: ' + str(history()))
        except Exception as e:
            self.output.append('Unblock error: ' + str(e))
