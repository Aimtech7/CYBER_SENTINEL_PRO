from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
)
import pyqtgraph as pg
from core.threatintel.apis import vt_ip, vt_domain, vt_url, vt_file, shodan_ip, abuseipdb_ip
from core.feeds.feeds import otx_general
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

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)

        self.chart = pg.PlotWidget(); self.chart.setBackground('#0f1320')
        root.addWidget(self.chart)

        check_btn.clicked.connect(self.check)

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
            res = {'virustotal': vt, 'shodan': sh, 'abuseipdb': ab}
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0
        elif val.startswith('http'):
            vt = vt_url(val)
            res = {'virustotal': vt}
            try:
                score = vt['data']['attributes']['stats']['malicious']
            except Exception:
                score = 0
        elif len(val) in (32, 40, 64):
            vt = vt_file(val)
            res = {'virustotal': vt}
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0
        else:
            vt = vt_domain(val)
            res = {'virustotal': vt}
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0

        # OTX enrichment
        try:
            if val.count('.') == 3 and all(x.isdigit() for x in val.split('.')):
                res['otx'] = otx_general('IPv4', val)
            elif val.startswith('http'):
                res['otx'] = otx_general('URL', val)
            elif len(val) in (32, 40, 64):
                res['otx'] = otx_general('file', val)
            else:
                res['otx'] = otx_general('domain', val)
        except Exception:
            pass
        self.output.setText(str(res))
        self.chart.clear()
        bars = pg.BarGraphItem(x=[0, 1], height=[score, max(0, 100 - score)], width=0.8, brush=pg.mkBrush('#4db5ff'))
        self.chart.addItem(bars)
        text = str(res)
        ai = summarize('Threat Intel Summary', text)
        if ai:
            self.output.append('\nAI Summary:\n' + ai)
