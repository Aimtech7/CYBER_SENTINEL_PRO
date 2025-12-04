import socket
import threading
import time
from typing import List, Dict, Callable


class _TCPHandler(threading.Thread):
    def __init__(self, host: str, port: int, on_event: Callable[[Dict], None]):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.on_event = on_event
        self._stop = False
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self):
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen(50)
        except Exception as e:
            self.on_event({'ts': time.time(), 'type': 'error', 'detail': str(e), 'port': self.port})
            return
        while not self._stop:
            try:
                self.sock.settimeout(1.0)
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except Exception as e:
                self.on_event({'ts': time.time(), 'type': 'error', 'detail': str(e), 'port': self.port})
                continue
            try:
                data = conn.recv(1024)
                self.on_event({'ts': time.time(), 'type': 'connection', 'addr': addr[0], 'port': self.port, 'data': data.hex()})
                conn.sendall(b"220 Service ready\r\n")
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def stop(self):
        self._stop = True
        try:
            self.sock.close()
        except Exception:
            pass


class HoneypotManager:
    def __init__(self, host: str = '0.0.0.0', ports: List[int] = None):
        self.host = host
        self.ports = ports or [8080, 2222, 2323, 4455]
        self.handlers: List[_TCPHandler] = []
        self.events: List[Dict] = []

    def start(self, on_event: Callable[[Dict], None]):
        self.stop()
        self.events.clear()
        self.handlers = []
        for p in self.ports:
            h = _TCPHandler(self.host, p, lambda e: self._emit(e, on_event))
            self.handlers.append(h)
            h.start()

    def _emit(self, e: Dict, on_event: Callable[[Dict], None]):
        self.events.append(e)
        on_event(e)

    def stop(self):
        for h in self.handlers:
            h.stop()
        self.handlers = []

