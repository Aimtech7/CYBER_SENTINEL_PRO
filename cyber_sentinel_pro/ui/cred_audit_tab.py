from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from core.cred.audit import entropy, policy_check, hibp_pwned


class CredAuditTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Credential Audit')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)
        self.input = QLineEdit(); self.input.setPlaceholderText('Enter password (not stored)')
        root.addWidget(self.input)
        check_btn = QPushButton('Check')
        root.addWidget(check_btn)
        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)
        check_btn.clicked.connect(self.check)

    def check(self):
        p = self.input.text()
        e = entropy(p)
        pol = policy_check(p)
        count = hibp_pwned(p)
        self.output.setText(f'Entropy: {e:.2f}\nPolicy: {pol}\nPwned Count: {count}')

