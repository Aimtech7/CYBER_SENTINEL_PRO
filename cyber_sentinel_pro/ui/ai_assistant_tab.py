import os
import asyncio
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QLineEdit, QPushButton, QFileDialog
from core.ai.assistant import explain_threat, summarize_logs, analyze_packets, risk_rating, recommend_actions, qa


class AIWorker(QThread):
    done = pyqtSignal(str)
    def __init__(self, mode: str, payload: dict):
        super().__init__()
        self.mode = mode
        self.payload = payload
    def run(self):
        async def go():
            if self.mode == 'explain':
                return await explain_threat(self.payload.get('context', ''))
            if self.mode == 'summarize':
                return await summarize_logs(self.payload.get('title', ''), self.payload.get('logs', ''))
            if self.mode == 'packets':
                return await analyze_packets(self.payload.get('summary', ''))
            if self.mode == 'risk':
                return await risk_rating(self.payload.get('evidence', {}))
            if self.mode == 'recommend':
                return await recommend_actions(self.payload.get('context', ''))
            if self.mode == 'qa':
                return await qa(self.payload.get('query', ''), self.payload.get('data', ''))
            return None
        res = asyncio.run(go())
        self.done.emit(res or '')


class AIAssistantTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        title = QLabel('AI Threat Assistant')
        title.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(title)

        self.chat = QTextEdit(); self.chat.setReadOnly(True)
        root.addWidget(self.chat)

        inp_row = QHBoxLayout()
        self.input = QLineEdit(); self.input.setPlaceholderText('Ask a question or paste context...')
        send_btn = QPushButton('Ask')
        inp_row.addWidget(self.input)
        inp_row.addWidget(send_btn)
        root.addLayout(inp_row)

        act_row = QHBoxLayout()
        self.ctx = QTextEdit(); self.ctx.setPlaceholderText('Threat/log/packet context')
        act_row.addWidget(self.ctx)
        right = QVBoxLayout()
        explain_btn = QPushButton('Explain Threat')
        summarize_btn = QPushButton('Summarize Logs')
        packets_btn = QPushButton('Analyze Packets')
        risk_btn = QPushButton('Rate Risk')
        recommend_btn = QPushButton('Recommend Actions')
        export_btn = QPushButton('Export Chat')
        right.addWidget(explain_btn)
        right.addWidget(summarize_btn)
        right.addWidget(packets_btn)
        right.addWidget(risk_btn)
        right.addWidget(recommend_btn)
        right.addWidget(export_btn)
        wrap = QHBoxLayout()
        wrap.addLayout(act_row, 1)
        wrap.addLayout(right)
        root.addLayout(wrap)

        send_btn.clicked.connect(self.ask)
        explain_btn.clicked.connect(lambda: self._run('explain'))
        summarize_btn.clicked.connect(lambda: self._run('summarize'))
        packets_btn.clicked.connect(lambda: self._run('packets'))
        risk_btn.clicked.connect(lambda: self._run('risk'))
        recommend_btn.clicked.connect(lambda: self._run('recommend'))
        export_btn.clicked.connect(self.export_chat)

    def ask(self):
        q = self.input.text().strip()
        data = self.ctx.toPlainText()
        if not q:
            return
        self.chat.append('You: ' + q)
        w = AIWorker('qa', {'query': q, 'data': data})
        w.done.connect(lambda s: self.chat.append('AI: ' + (s or ''))) 
        w.start()

    def _run(self, mode: str):
        c = self.ctx.toPlainText()
        self.chat.append('Running ' + mode)
        payload = {'context': c, 'title': 'Logs', 'logs': c, 'summary': c, 'evidence': {'data': c}}
        w = AIWorker(mode, payload)
        w.done.connect(lambda s: self.chat.append('AI: ' + (s or ''))) 
        w.start()

    def export_chat(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Export Chat', os.path.expanduser('~'), 'Text (*.txt)')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write(self.chat.toPlainText())
        except Exception:
            pass
