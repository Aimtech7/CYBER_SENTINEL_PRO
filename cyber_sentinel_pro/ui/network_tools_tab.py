import subprocess
import threading
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QHBoxLayout


class NetworkToolsTab(QWidget):
    def __init__(self):
        super().__init__()
        self._init_ui()

    def _init_ui(self):
        root = QVBoxLayout(self)
        header = QLabel('Network Tools')
        header.setStyleSheet('font-size:18px; font-weight:bold; color:#9bd1ff')
        root.addWidget(header)

        # Ping controls
        ping_row = QHBoxLayout()
        self.ping_host = QLineEdit(); self.ping_host.setPlaceholderText('Host to ping (e.g., 8.8.8.8)')
        ping_btn = QPushButton('Ping')
        ping_row.addWidget(self.ping_host)
        ping_row.addWidget(ping_btn)
        root.addLayout(ping_row)

        # Speed test controls
        speed_btn = QPushButton('Run Speed Test')
        root.addWidget(speed_btn)

        self.out = QTextEdit(); self.out.setReadOnly(True)
        root.addWidget(self.out)

        ping_btn.clicked.connect(self._do_ping)
        speed_btn.clicked.connect(self._do_speedtest)

    def _do_ping(self):
        host = (self.ping_host.text() or '').strip()
        if not host:
            self.out.append('Enter a host to ping.')
            return
        def run():
            try:
                # Windows ping -n 4
                proc = subprocess.run(['ping', '-n', '4', host], capture_output=True, text=True)
                txt = proc.stdout or proc.stderr
                avg = ''
                for ln in (txt or '').splitlines():
                    if 'Average' in ln or 'Average =' in ln:
                        avg = ln.strip()
                        break
                self.out.append('Ping result:\n' + (txt or '').strip())
                if avg:
                    self.out.append('Summary: ' + avg)
            except Exception as e:
                self.out.append(f'Ping error: {e}')
        threading.Thread(target=run, daemon=True).start()

    def _do_speedtest(self):
        def run():
            try:
                import speedtest
                st = speedtest.Speedtest()
                st.get_best_server()
                d = st.download(); u = st.upload(); p = st.results.ping
                mbps_d = d / 1_000_000.0
                mbps_u = u / 1_000_000.0
                self.out.append(f'Speed Test:\nDownload: {mbps_d:.2f} Mbps\nUpload: {mbps_u:.2f} Mbps\nPing: {p} ms')
            except Exception as e:
                self.out.append(f'Speed test error: {e}')
        threading.Thread(target=run, daemon=True).start()
