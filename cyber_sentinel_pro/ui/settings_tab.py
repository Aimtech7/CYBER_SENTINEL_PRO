from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QFormLayout, QLineEdit, QPushButton, QVBoxLayout, QLabel, QHBoxLayout, QCheckBox, QTextEdit
)
from core.utils.secure_storage import save_secret, load_secret, save_setting, load_setting


class SettingsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('Settings')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)

        self.openai_edit = QLineEdit()
        self.openai_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.openai_edit.setPlaceholderText('sk-...')
        existing = load_secret('openai_api_key')
        if existing:
            self.openai_edit.setText(existing)
        form.addRow('OpenAI API Key', self.openai_edit)

        self.vt_edit = QLineEdit()
        self.vt_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.vt_edit.setPlaceholderText('VirusTotal API Key (optional)')
        if (vt := load_secret('virustotal_api_key')):
            self.vt_edit.setText(vt)
        form.addRow('VirusTotal Key', self.vt_edit)

        self.shodan_edit = QLineEdit()
        self.shodan_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.shodan_edit.setPlaceholderText('Shodan API Key (optional)')
        if (sk := load_secret('shodan_api_key')):
            self.shodan_edit.setText(sk)
        form.addRow('Shodan Key', self.shodan_edit)

        self.abuse_edit = QLineEdit()
        self.abuse_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.abuse_edit.setPlaceholderText('AbuseIPDB API Key (optional)')
        if (ak := load_secret('abuseipdb_api_key')):
            self.abuse_edit.setText(ak)
        form.addRow('AbuseIPDB Key', self.abuse_edit)

        self.model_edit = QLineEdit()
        self.model_edit.setPlaceholderText('Leave blank for auto-selection')
        self.model_edit.setText(load_setting('openai_model', ''))
        form.addRow('OpenAI Model (optional)', self.model_edit)

        self.profile_edit = QLineEdit()
        self.profile_edit.setPlaceholderText('Profile name (optional)')
        self.profile_edit.setText(load_setting('profile_name', ''))
        form.addRow('Profile Name', self.profile_edit)

        self.role_edit = QLineEdit()
        self.role_edit.setPlaceholderText('admin or viewer')
        self.role_edit.setText(load_setting('role', 'admin'))
        form.addRow('Role', self.role_edit)

        self.hp_autostart = QCheckBox()
        self.hp_autostart.setChecked(load_setting('honeypot_autostart', True))
        form.addRow('Autostart Honeypot', self.hp_autostart)
        self.hp_ports = QLineEdit(); self.hp_ports.setPlaceholderText('8080,2222,2323,4455')
        self.hp_ports.setText(load_setting('honeypot_ports', '8080,2222,2323,4455'))
        form.addRow('Honeypot Ports', self.hp_ports)

        self.slack_webhook = QLineEdit(); self.slack_webhook.setPlaceholderText('https://hooks.slack.com/services/...')
        self.slack_webhook.setText(load_setting('slack_webhook_url', ''))
        form.addRow('Slack Webhook URL', self.slack_webhook)

        self.smtp_host = QLineEdit(); self.smtp_host.setPlaceholderText('smtp.example.com')
        self.smtp_host.setText(load_setting('smtp_host', ''))
        form.addRow('SMTP Host', self.smtp_host)
        self.smtp_port = QLineEdit(); self.smtp_port.setPlaceholderText('587')
        self.smtp_port.setText(str(load_setting('smtp_port', 0) or ''))
        form.addRow('SMTP Port', self.smtp_port)
        self.smtp_user = QLineEdit(); self.smtp_user.setPlaceholderText('user@example.com')
        self.smtp_user.setText(load_setting('smtp_user', ''))
        form.addRow('SMTP User', self.smtp_user)
        self.smtp_pass = QLineEdit(); self.smtp_pass.setEchoMode(QLineEdit.EchoMode.Password); self.smtp_pass.setPlaceholderText('password')
        self.smtp_pass.setText(load_setting('smtp_pass', ''))
        form.addRow('SMTP Password', self.smtp_pass)
        self.smtp_to = QLineEdit(); self.smtp_to.setPlaceholderText('alerts@example.com')
        self.smtp_to.setText(load_setting('smtp_to', ''))
        form.addRow('SMTP To', self.smtp_to)

        self.misp_url = QLineEdit(); self.misp_url.setPlaceholderText('https://misp.example.org')
        self.misp_url.setText(load_setting('misp_url', ''))
        form.addRow('MISP URL', self.misp_url)
        self.misp_key = QLineEdit(); self.misp_key.setEchoMode(QLineEdit.EchoMode.Password); self.misp_key.setPlaceholderText('MISP API Key')
        self.misp_key.setText(load_secret('misp_api_key') or '')
        form.addRow('MISP API Key', self.misp_key)

        root.addLayout(form)

        btns = QHBoxLayout()
        save_btn = QPushButton('Save Settings')
        test_btn = QPushButton('Test OpenAI')
        test_all_btn = QPushButton('Test All APIs')
        self.dark_toggle = QCheckBox('Dark Mode')
        self.dark_toggle.setChecked(load_setting('dark_mode', True))
        self.safe_mode_toggle = QCheckBox('Safe Mode (restrict dangerous actions)')
        self.safe_mode_toggle.setChecked(load_setting('safe_mode', True))
        btns.addWidget(save_btn)
        btns.addWidget(test_btn)
        btns.addWidget(test_all_btn)
        btns.addWidget(self.dark_toggle)
        btns.addWidget(self.safe_mode_toggle)
        root.addLayout(btns)

        self.status = QLabel('')
        root.addWidget(self.status)
        self.audit_view = QTextEdit(); self.audit_view.setReadOnly(True)
        root.addWidget(self.audit_view)

        save_btn.clicked.connect(self.save)
        test_btn.clicked.connect(self.test_openai)
        test_all_btn.clicked.connect(self.test_all)
        view_audit_btn = QPushButton('View Audit Log'); btns.addWidget(view_audit_btn)
        view_audit_btn.clicked.connect(self.view_audit)

    def save(self):
        save_secret('openai_api_key', self.openai_edit.text().strip())
        save_secret('virustotal_api_key', self.vt_edit.text().strip())
        save_secret('shodan_api_key', self.shodan_edit.text().strip())
        save_secret('abuseipdb_api_key', self.abuse_edit.text().strip())
        save_setting('openai_model', self.model_edit.text().strip())
        save_setting('profile_name', self.profile_edit.text().strip())
        save_setting('honeypot_autostart', self.hp_autostart.isChecked())
        save_setting('honeypot_ports', self.hp_ports.text().strip() or '8080,2222,2323,4455')
        save_setting('dark_mode', self.dark_toggle.isChecked())
        save_setting('role', self.role_edit.text().strip() or 'admin')
        save_setting('safe_mode', self.safe_mode_toggle.isChecked())
        save_setting('slack_webhook_url', self.slack_webhook.text().strip())
        try:
            p = int(self.smtp_port.text().strip() or '0')
        except Exception:
            p = 0
        save_setting('smtp_host', self.smtp_host.text().strip())
        save_setting('smtp_port', p)
        save_setting('smtp_user', self.smtp_user.text().strip())
        save_setting('smtp_pass', self.smtp_pass.text().strip())
        save_setting('smtp_to', self.smtp_to.text().strip())
        save_setting('misp_url', self.misp_url.text().strip())
        save_secret('misp_api_key', self.misp_key.text().strip())
        self.status.setText('Settings saved securely.')

    def test_openai(self):
        from core.utils.ai_client import probe
        ok, msg = probe()
        self.status.setText(msg)

    def test_all(self):
        from core.threatintel.apis import vt_domain, shodan_ip, abuseipdb_ip
        ok = []
        vt = vt_domain('example.com')
        if vt and 'data' in vt:
            ok.append('VirusTotal')
        sh = shodan_ip('8.8.8.8')
        if sh and ('ip_str' in sh or 'data' in sh):
            ok.append('Shodan')
        ab = abuseipdb_ip('1.1.1.1')
        if ab and ('data' in ab):
            ok.append('AbuseIPDB')
        self.status.setText('APIs OK: ' + ', '.join(ok) if ok else 'No APIs validated. Check keys.')

    def view_audit(self):
        import os
        home = os.path.expanduser('~')
        path = os.path.join(home, '.cyber_sentinel_pro', 'audit.log')
        try:
            if os.path.exists(path):
                with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
                    lines = fh.read().splitlines()
                tail = '\n'.join(lines[-500:])
                self.audit_view.setPlainText(tail or 'Audit log is empty.')
                self.status.setText('Audit log loaded.')
            else:
                self.audit_view.setPlainText('No audit log found.')
                self.status.setText('No audit log found.')
        except Exception as e:
            self.status.setText(f'Audit load error: {e}')
