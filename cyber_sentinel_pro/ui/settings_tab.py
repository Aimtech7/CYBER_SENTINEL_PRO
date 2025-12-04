from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QWidget, QFormLayout, QLineEdit, QPushButton, QVBoxLayout, QLabel, QHBoxLayout
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
        self.model_edit.setPlaceholderText('gpt-4o-mini')
        self.model_edit.setText(load_setting('openai_model', 'gpt-4o-mini'))
        form.addRow('OpenAI Model', self.model_edit)

        root.addLayout(form)

        btns = QHBoxLayout()
        save_btn = QPushButton('Save Settings')
        test_btn = QPushButton('Test OpenAI')
        btns.addWidget(save_btn)
        btns.addWidget(test_btn)
        root.addLayout(btns)

        self.status = QLabel('')
        root.addWidget(self.status)

        save_btn.clicked.connect(self.save)
        test_btn.clicked.connect(self.test_openai)

    def save(self):
        save_secret('openai_api_key', self.openai_edit.text().strip())
        save_secret('virustotal_api_key', self.vt_edit.text().strip())
        save_secret('shodan_api_key', self.shodan_edit.text().strip())
        save_secret('abuseipdb_api_key', self.abuse_edit.text().strip())
        save_setting('openai_model', self.model_edit.text().strip() or 'gpt-4o-mini')
        self.status.setText('Settings saved securely.')

    def test_openai(self):
        from core.utils.ai_client import summarize
        res = summarize('Test', 'This is a test of the OpenAI integration.')
        if res:
            self.status.setText('OpenAI test succeeded.')
        else:
            self.status.setText('OpenAI test failed. Check API key and network.')

