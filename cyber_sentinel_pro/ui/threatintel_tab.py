from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QTableWidget, QTableWidgetItem, QProgressBar, QFileDialog
)
import pyqtgraph as pg
from core.threatintel.apis import vt_ip, vt_domain, vt_url, vt_file, shodan_ip, abuseipdb_ip, otx_general, otx_passive_dns_domain, whois_rdap, malwarebazaar_hash, misp_search
from core.utils.ai_client import summarize
from core.utils.secure_storage import load_setting, append_audit


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
        self.pdns_btn = QPushButton('Passive DNS')
        self.whois_btn = QPushButton('WHOIS/RDAP')
        self.mb_btn = QPushButton('MalwareBazaar')
        self.misp_btn = QPushButton('MISP Search')
        actions.addWidget(self.block_btn)
        actions.addWidget(self.unblock_btn)
        actions.addWidget(self.pdns_btn)
        actions.addWidget(self.whois_btn)
        actions.addWidget(self.mb_btn)
        actions.addWidget(self.misp_btn)
        root.addLayout(actions)

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)
        self.log_view = QTextEdit(); self.log_view.setReadOnly(True)
        root.addWidget(self.log_view)

        self.loader = QProgressBar(); self.loader.setRange(0, 0); self.loader.hide()
        root.addWidget(self.loader)

        tables = QHBoxLayout()
        # Key/Value small tables for common sources
        self.vt_table = QTableWidget(0, 2)
        self.vt_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.shodan_table = QTableWidget(0, 2)
        self.shodan_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.abuse_table = QTableWidget(0, 2)
        self.abuse_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.otx_table = QTableWidget(0, 2)
        self.otx_table.setHorizontalHeaderLabels(['Field', 'Value'])
        self.mb_table = QTableWidget(0, 4)
        self.mb_table.setHorizontalHeaderLabels(['sha256', 'mime', 'signature', 'first_seen'])
        self.misp_table = QTableWidget(0, 5)
        self.misp_table.setHorizontalHeaderLabels(['type', 'value', 'category', 'event_id', 'timestamp'])
        tables.addWidget(self.vt_table)
        tables.addWidget(self.shodan_table)
        tables.addWidget(self.abuse_table)
        tables.addWidget(self.otx_table)
        tables.addWidget(self.mb_table)
        tables.addWidget(self.misp_table)
        root.addLayout(tables)

        self.chart = pg.PlotWidget(); self.chart.setBackground('#0f1320')
        root.addWidget(self.chart)

        check_btn.clicked.connect(self.check)
        self.block_btn.clicked.connect(self.block_ip)
        self.unblock_btn.clicked.connect(self.unblock_ip)
        self.pdns_btn.clicked.connect(self.passive_dns)
        self.whois_btn.clicked.connect(self.do_whois)
        self.mb_btn.clicked.connect(self.malwarebazaar)
        self.misp_btn.clicked.connect(self.misp_lookup)

        export_row = QHBoxLayout()
        export_threat_btn = QPushButton('Export Threat Tables (CSV)')
        export_row.addWidget(export_threat_btn)
        root.addLayout(export_row)
        export_threat_btn.clicked.connect(self.export_threat_tables)

    def check(self):
        val = self.input_edit.text().strip()
        if not val:
            return
        self.loader.show()
        res = None
        score = 0
        if val.count('.') == 3 and all(x.isdigit() for x in val.split('.')):
            vt = vt_ip(val)
            sh = shodan_ip(val)
            ab = abuseipdb_ip(val)
            otx = otx_general('IPv4', val)
            res = {'virustotal': vt, 'shodan': sh, 'abuseipdb': ab, 'otx': otx}
            self._render_kv(self.vt_table, self._flatten_vt_ip(vt))
            self._render_kv(self.shodan_table, self._flatten_shodan(sh))
            self._render_kv(self.abuse_table, self._flatten_abuse(ab))
            self._render_kv(self.otx_table, self._flatten_otx(otx))
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0
        elif val.startswith('http'):
            vt = vt_url(val)
            otx = otx_general('url', val)
            res = {'virustotal': vt, 'otx': otx}
            self._render_kv(self.vt_table, self._flatten_vt_url(vt))
            self._render_kv(self.otx_table, self._flatten_otx(otx))
            try:
                score = vt['data']['attributes']['stats']['malicious']
            except Exception:
                score = 0
        elif len(val) in (32, 40, 64):
            vt = vt_file(val)
            otx = otx_general('file', val)
            res = {'virustotal': vt, 'otx': otx}
            self._render_kv(self.vt_table, self._flatten_vt_file(vt))
            self._render_kv(self.otx_table, self._flatten_otx(otx))
            try:
                score = vt['data']['attributes']['last_analysis_stats']['malicious']
            except Exception:
                score = 0
        else:
            vt = vt_domain(val)
            otx = otx_general('domain', val)
            res = {'virustotal': vt, 'otx': otx}
            self._render_kv(self.vt_table, self._flatten_vt_domain(vt))
            self._render_kv(self.otx_table, self._flatten_otx(otx))
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
        try:
            from core.utils.attack_map import map_finding
            if score > 0:
                tech = map_finding('c2_traffic')
                if tech:
                    self.output.append('MITRE: ' + tech)
            sev = 'info'
            if score > 0:
                sev = 'danger'
            color = {'info': '#9bd1ff', 'warning': '#e0a800', 'danger': '#ff4d4d'}[sev]
            self.log_view.append(f"<span style='color:{color}'>[{sev.upper()}] Score={score} {val}</span>")
        except Exception:
            pass
        self.loader.hide()

    def export_threat_tables(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export Threat Tables CSV', '', 'CSV (*.csv)')
        if not path:
            return
        import csv
        def dump(table: QTableWidget, name: str, writer):
            writer.writerow([name])
            headers = [table.horizontalHeaderItem(i).text() for i in range(table.columnCount())]
            writer.writerow(headers)
            for r in range(table.rowCount()):
                row = []
                for c in range(table.columnCount()):
                    it = table.item(r, c)
                    row.append(it.text() if it else '')
                writer.writerow(row)
        with open(path, 'w', newline='', encoding='utf-8') as fh:
            w = csv.writer(fh)
            dump(self.vt_table, 'VirusTotal', w)
            dump(self.shodan_table, 'Shodan', w)
            dump(self.abuse_table, 'AbuseIPDB', w)
            dump(self.otx_table, 'OTX', w)
            dump(self.mb_table, 'MalwareBazaar', w)
            dump(self.misp_table, 'MISP', w)

    def _render_kv(self, table: QTableWidget, kv: dict):
        try:
            table.setRowCount(0)
            for k, v in list(kv.items())[:200]:
                i = table.rowCount(); table.insertRow(i)
                table.setItem(i, 0, QTableWidgetItem(str(k)))
                table.setItem(i, 1, QTableWidgetItem(str(v)))
            table.setSortingEnabled(True)
        except Exception:
            pass

    def _flatten_vt_ip(self, vt):
        d = {}
        try:
            a = vt.get('data', {}).get('attributes', {}) if isinstance(vt, dict) else {}
            d['country'] = a.get('country')
            d['as_owner'] = a.get('as_owner')
            d['malicious'] = a.get('last_analysis_stats', {}).get('malicious')
        except Exception:
            pass
        return d

    def _flatten_vt_domain(self, vt):
        d = {}
        try:
            a = vt.get('data', {}).get('attributes', {}) if isinstance(vt, dict) else {}
            d['registrar'] = a.get('registrar')
            d['tld'] = a.get('tld')
            d['malicious'] = a.get('last_analysis_stats', {}).get('malicious')
        except Exception:
            pass
        return d

    def _flatten_vt_url(self, vt):
        d = {}
        try:
            a = vt.get('data', {}).get('attributes', {}) if isinstance(vt, dict) else {}
            d['status'] = a.get('status')
            d['malicious'] = a.get('stats', {}).get('malicious')
        except Exception:
            pass
        return d

    def _flatten_vt_file(self, vt):
        d = {}
        try:
            a = vt.get('data', {}).get('attributes', {}) if isinstance(vt, dict) else {}
            d['type'] = a.get('type_description')
            d['size'] = a.get('size')
            d['malicious'] = a.get('last_analysis_stats', {}).get('malicious')
        except Exception:
            pass
        return d

    def _flatten_shodan(self, sh):
        d = {}
        try:
            if isinstance(sh, dict):
                d['ip'] = sh.get('ip_str') or ''
                d['country'] = sh.get('country_name') or ''
                d['org'] = sh.get('org') or ''
                d['open_ports'] = ','.join([str(p.get('port')) for p in sh.get('data', []) if isinstance(p, dict)])
        except Exception:
            pass
        return d

    def _flatten_abuse(self, ab):
        d = {}
        try:
            a = ab.get('data', {}) if isinstance(ab, dict) else {}
            d['ipAddress'] = a.get('ipAddress')
            d['abuseConfidenceScore'] = a.get('abuseConfidenceScore')
            d['totalReports'] = a.get('totalReports')
        except Exception:
            pass
        return d

    def _flatten_otx(self, otx):
        d = {}
        try:
            if isinstance(otx, dict):
                d['pulse_count'] = len(otx.get('pulse_info', {}).get('pulses', []))
                d['indicator'] = otx.get('indicator')
                d['type'] = otx.get('type')
        except Exception:
            pass
        return d

    def block_ip(self):
        val = self.input_edit.text().strip()
        parts = val.split('.')
        if not val or val.count('.') != 3 or not all(p.isdigit() for p in parts):
            return
        if load_setting('safe_mode', True):
            QMessageBox.warning(self, 'Restricted', 'Safe Mode enabled')
            return
        if (load_setting('role', 'admin') or '').lower() != 'admin':
            QMessageBox.warning(self, 'Restricted', 'Admin role required')
            return
        ok = QMessageBox.question(self, 'Confirm Block', f'AI recommends blocking {val}. Proceed?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.utils.firewall import block_ip, history
            res = block_ip(val)
            self.output.append('Block result: ' + str(res))
            self.output.append('History: ' + str(history()))
            append_audit({'ts': time.time(), 'action': 'block_ip', 'ip': val, 'result': bool(res)})
        except Exception as e:
            self.output.append('Block error: ' + str(e))

    def unblock_ip(self):
        val = self.input_edit.text().strip()
        parts = val.split('.')
        if not val or val.count('.') != 3 or not all(p.isdigit() for p in parts):
            return
        if load_setting('safe_mode', True):
            QMessageBox.warning(self, 'Restricted', 'Safe Mode enabled')
            return
        if (load_setting('role', 'admin') or '').lower() != 'admin':
            QMessageBox.warning(self, 'Restricted', 'Admin role required')
            return
        ok = QMessageBox.question(self, 'Confirm Unblock', f'Unblock {val}?')
        if ok != QMessageBox.StandardButton.Yes:
            return
        try:
            from core.utils.firewall import unblock_ip, history
            res = unblock_ip(val)
            self.output.append('Unblock result: ' + str(res))
            self.output.append('History: ' + str(history()))
            append_audit({'ts': time.time(), 'action': 'unblock_ip', 'ip': val, 'result': bool(res)})
        except Exception as e:
            self.output.append('Unblock error: ' + str(e))

    def passive_dns(self):
        val = self.input_edit.text().strip()
        if not val:
            return
        self.loader.show()
        try:
            res = otx_passive_dns_domain(val)
            self.output.append('Passive DNS: ' + str(res))
        except Exception as e:
            self.output.append('Passive DNS error: ' + str(e))
        self.loader.hide()

    def do_whois(self):
        val = self.input_edit.text().strip()
        if not val:
            return
        self.loader.show()
        try:
            res = whois_rdap(val)
            self.output.append('WHOIS/RDAP: ' + str(res))
        except Exception as e:
            self.output.append('WHOIS error: ' + str(e))
        self.loader.hide()

    def malwarebazaar(self):
        val = self.input_edit.text().strip()
        if not val:
            return
        self.loader.show()
        try:
            res = malwarebazaar_hash(val)
            self.output.append('MalwareBazaar: ' + str(res))
            self._render_mb_table(res)
        except Exception as e:
            self.output.append('MB error: ' + str(e))
        self.loader.hide()

    def misp_lookup(self):
        val = self.input_edit.text().strip()
        if not val:
            return
        self.loader.show()
        try:
            res = misp_search(val)
            self.output.append('MISP: ' + str(res))
            self._render_misp_table(res)
        except Exception as e:
            self.output.append('MISP error: ' + str(e))
        self.loader.hide()

    def _render_mb_table(self, res):
        try:
            rows = []
            if isinstance(res, dict):
                data = res.get('data') or []
                for d in data:
                    rows.append([
                        d.get('sha256') or d.get('sha1') or d.get('md5') or '',
                        d.get('file_type_mime') or '',
                        d.get('signature') or '',
                        d.get('first_seen') or '',
                    ])
            self.mb_table.setRowCount(0)
            for row in rows[:200]:
                i = self.mb_table.rowCount(); self.mb_table.insertRow(i)
                for j, val in enumerate(row):
                    self.mb_table.setItem(i, j, QTableWidgetItem(str(val)))
        except Exception:
            pass

    def _render_misp_table(self, res):
        try:
            attrs = []
            if isinstance(res, dict):
                if 'response' in res and isinstance(res['response'], dict):
                    attrs = res['response'].get('Attribute') or []
                elif 'Attribute' in res and isinstance(res['Attribute'], list):
                    attrs = res['Attribute']
                elif 'data' in res and isinstance(res['data'], dict):
                    attrs = res['data'].get('Attribute') or []
            self.misp_table.setRowCount(0)
            for a in attrs[:200]:
                i = self.misp_table.rowCount(); self.misp_table.insertRow(i)
                cols = [
                    a.get('type') or '',
                    a.get('value') or '',
                    a.get('category') or '',
                    str(a.get('event_id') or ''),
                    str(a.get('timestamp') or ''),
                ]
                for j, val in enumerate(cols):
                    self.misp_table.setItem(i, j, QTableWidgetItem(str(val)))
        except Exception:
            pass
