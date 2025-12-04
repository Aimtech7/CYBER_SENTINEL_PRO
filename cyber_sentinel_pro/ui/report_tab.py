from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QTextEdit, QPushButton, QCheckBox, QFileDialog
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from core.utils.ai_client import summarize


class ReportTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Report Builder')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        self.title = QLineEdit(); self.title.setPlaceholderText('Report Title')
        root.addWidget(self.title)
        self.body = QTextEdit(); self.body.setPlaceholderText('Findings, risks, evidence...')
        root.addWidget(self.body)
        self.include_ai = QCheckBox('Include AI summary')
        root.addWidget(self.include_ai)
        gen = QPushButton('Generate PDF')
        root.addWidget(gen)
        self.status = QLabel('')
        root.addWidget(self.status)

        gen.clicked.connect(self.generate_pdf)

    def generate_pdf(self):
        path, _ = QFileDialog.getSaveFileName(self, 'Save Report', '', 'PDF (*.pdf)')
        if not path:
            return
        title = self.title.text().strip() or 'Security Report'
        body = self.body.toPlainText().strip()
        ai_text = ''
        if self.include_ai.isChecked() and body:
            ai = summarize(title, body, max_tokens=600)
            if ai:
                ai_text = ai
        c = canvas.Canvas(path, pagesize=letter)
        width, height = letter
        y = height - 50
        c.setFont('Helvetica-Bold', 16)
        c.drawString(50, y, title)
        y -= 30
        c.setFont('Helvetica', 10)
        for ln in (body or '').splitlines():
            c.drawString(50, y, ln[:1000])
            y -= 14
            if y < 80:
                c.showPage(); y = height - 50
        if ai_text:
            y -= 20
            c.setFont('Helvetica-Bold', 12)
            c.drawString(50, y, 'AI Summary')
            y -= 18
            c.setFont('Helvetica', 10)
            for ln in ai_text.splitlines():
                c.drawString(50, y, ln[:1000])
                y -= 14
                if y < 80:
                    c.showPage(); y = height - 50
        c.showPage(); c.save()
        self.status.setText('Report saved.')
