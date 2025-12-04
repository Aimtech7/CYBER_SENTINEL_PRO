import os
import shlex
import subprocess
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit, QFileDialog, QComboBox, QLineEdit
)


class HashcatWorker(QThread):
    line = pyqtSignal(str)
    done = pyqtSignal(int)

    def __init__(self, cmd: str):
        super().__init__()
        self.cmd = cmd

    def run(self):
        proc = subprocess.Popen(shlex.split(self.cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            self.line.emit(line.rstrip())
        proc.wait()
        self.done.emit(proc.returncode)


class HashcatTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()
        self.hash_path = ''
        self.worker = None

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Password Cracking Controller (Hashcat)')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        top = QHBoxLayout()
        open_btn = QPushButton('Select Hash File')
        self.mode_combo = QComboBox(); self.mode_combo.addItems(['0 (Straight)', '3 (Brute-force)', '6 (Hybrid Wordlist + Mask)'])
        self.hash_type = QLineEdit(); self.hash_type.setPlaceholderText('Hash type (e.g., 0 for MD5)')
        start_btn = QPushButton('Start')
        show_btn = QPushButton('Show Recovered')
        top.addWidget(open_btn)
        top.addWidget(self.hash_type)
        top.addWidget(self.mode_combo)
        top.addWidget(start_btn)
        top.addWidget(show_btn)
        root.addLayout(top)

        self.output = QTextEdit(); self.output.setReadOnly(True)
        root.addWidget(self.output)

        open_btn.clicked.connect(self.select_hash)
        start_btn.clicked.connect(self.start)
        show_btn.clicked.connect(self.show)

    def select_hash(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Select Hash File', os.path.expanduser('~'), 'Text (*.txt);;All (*)')
        if path:
            self.hash_path = path
            self.output.append(f'Hash file: {path}')

    def start(self):
        if not self.hash_path:
            self.output.append('Select a hash file.')
            return
        hash_type = self.hash_type.text().strip() or '0'
        mode = self.mode_combo.currentText().split(' ')[0]
        wordlist, _ = QFileDialog.getOpenFileName(self, 'Select Wordlist', os.path.expanduser('~'), 'Text (*.txt);;All (*)')
        if not wordlist:
            self.output.append('Select a wordlist.')
            return
        cmd = f"hashcat -m {hash_type} -a {mode} {self.hash_path} {wordlist} --status --status-timer=5"
        self.worker = HashcatWorker(cmd)
        self.worker.line.connect(lambda s: self.output.append(s))
        self.worker.done.connect(lambda c: self.output.append(f'Exited with {c}'))
        self.worker.start()

    def show(self):
        if not self.hash_path:
            return
        cmd = f"hashcat --show {self.hash_path}"
        try:
            out = subprocess.check_output(shlex.split(cmd), text=True, stderr=subprocess.STDOUT)
            self.output.append('Recovered:\n' + out)
        except Exception as e:
            self.output.append(f'Failed: {e}')

