from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit
from core.webscan.fuzzer import fuzz


class WebFuzzTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Web Fuzzer')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)
        self.url = QLineEdit(); self.url.setPlaceholderText('https://target.example/path')
        self.param = QLineEdit(); self.param.setPlaceholderText('param')
        root.addWidget(self.url)
        root.addWidget(self.param)
        btn = QPushButton('Run Fuzz')
        root.addWidget(btn)
        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)
        btn.clicked.connect(self.run)

    def run(self):
        u = self.url.text().strip(); p = self.param.text().strip()
        if not (u and p):
            self.output.setText('Enter URL and parameter name')
            return
        res = fuzz(u, p)
        self.output.setText('\n'.join([str(x) for x in res]))

