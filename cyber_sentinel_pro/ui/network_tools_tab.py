import subprocess
import threading
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QHBoxLayout, QProgressBar


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

        cert_row = QHBoxLayout()
        self.cert_host = QLineEdit(); self.cert_host.setPlaceholderText('Host:Port for certificate check (e.g., example.com:443)')
        cert_btn = QPushButton('Check Certificate Expiry')
        cert_row.addWidget(self.cert_host)
        cert_row.addWidget(cert_btn)
        root.addLayout(cert_row)

        dns_row = QHBoxLayout()
        self.dns_host = QLineEdit(); self.dns_host.setPlaceholderText('Domain for DNS health (e.g., example.com)')
        dns_btn = QPushButton('DNS Health Check')
        dns_row.addWidget(self.dns_host)
        dns_row.addWidget(dns_btn)
        root.addLayout(dns_row)

        self.out = QTextEdit(); self.out.setReadOnly(True)
        root.addWidget(self.out)

        self.loader = QProgressBar(); self.loader.setRange(0,0); self.loader.hide()
        root.addWidget(self.loader)

        ping_btn.clicked.connect(self._do_ping)
        speed_btn.clicked.connect(self._do_speedtest)
        cert_btn.clicked.connect(self._check_cert)
        dns_btn.clicked.connect(self._dns_health)

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
                    self.out.append("<span style='color:#9bd1ff'>Summary: " + avg + "</span>")
            except Exception as e:
                self.out.append(f'Ping error: {e}')
        self.loader.show(); threading.Thread(target=lambda: (run(), self.loader.hide()), daemon=True).start()

    def _do_speedtest(self):
        def run():
            try:
                import speedtest
                st = speedtest.Speedtest()
                st.get_best_server()
                d = st.download(); u = st.upload(); p = st.results.ping
                mbps_d = d / 1_000_000.0
                mbps_u = u / 1_000_000.0
                self.out.append(f"<span style='color:#9bd1ff'>Speed Test:\nDownload: {mbps_d:.2f} Mbps\nUpload: {mbps_u:.2f} Mbps\nPing: {p} ms</span>")
            except Exception as e:
                self.out.append(f'Speed test error: {e}')
        self.loader.show(); threading.Thread(target=lambda: (run(), self.loader.hide()), daemon=True).start()

    def _check_cert(self):
        hostport = (self.cert_host.text() or '').strip()
        if ':' not in hostport:
            self.out.append('Enter host:port, e.g., example.com:443')
            return
        import ssl, socket, datetime
        def run():
            try:
                host, port_s = hostport.split(':', 1)
                port = int(port_s)
                ctx = ssl.create_default_context()
                with socket.create_connection((host, port)) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        cert = ssock.getpeercert()
                        not_after = cert.get('notAfter')
                        exp = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days = (exp - datetime.datetime.utcnow()).days
                        color = '#9bd1ff' if days > 30 else ('#e0a800' if days >= 7 else '#ff4d4d')
                        self.out.append(f"<span style='color:{color}'>Cert expires in {days} days ({exp})</span>")
            except Exception as e:
                self.out.append(f'Certificate check error: {e}')
        self.loader.show(); threading.Thread(target=lambda: (run(), self.loader.hide()), daemon=True).start()

    def _dns_health(self):
        domain = (self.dns_host.text() or '').strip()
        if not domain:
            self.out.append('Enter a domain for DNS health.')
            return
        import socket, time
        def run():
            try:
                t0 = time.time(); addrs = socket.getaddrinfo(domain, None); dt = (time.time() - t0) * 1000
                ips = sorted(list({a[4][0] for a in addrs}))
                color = '#9bd1ff' if dt < 100 else ('#e0a800' if dt < 500 else '#ff4d4d')
                self.out.append(f"<span style='color:{color}'>DNS OK ({dt:.1f} ms): {', '.join(ips)}</span>")
            except Exception as e:
                self.out.append(f'DNS health error: {e}')
        self.loader.show(); threading.Thread(target=lambda: (run(), self.loader.hide()), daemon=True).start()
