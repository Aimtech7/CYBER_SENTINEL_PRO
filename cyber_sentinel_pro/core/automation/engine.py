import time
import threading
import json
import os
import queue
from typing import Optional, Dict
from core.utils.secure_storage import load_setting, save_setting
try:
    from core.siem.analyzer import analyze_log_line
except Exception:
    analyze_log_line = None
from core.threatintel.apis import vt_ip
from core.malware.sandbox import file_hashes, extract_strings, extract_iocs
from core.utils.ai_client import summarize


class AutomationTask:
    def __init__(self, name: str, settings_key: str):
        self.name = name
        self.settings_key = settings_key
        self.running = False
        self.last_run = 0.0
        self.thread: Optional[threading.Thread] = None
        self.log_q: queue.Queue[str] = queue.Queue()

    def settings(self) -> Dict:
        return load_setting(self.settings_key, {}) or {}

    def update_settings(self, s: Dict):
        save_setting(self.settings_key, s)

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _emit(self, s: str):
        try:
            self.log_q.put_nowait(s)
        except Exception:
            pass

    def _run_once(self):
        pass

    def _run_loop(self):
        while self.running:
            self.last_run = time.time()
            try:
                self._run_once()
            except Exception as e:
                self._emit(f'Error: {e}')
            time.sleep(self.settings().get('interval', 5))


class SIEMMonitor(AutomationTask):
    def __init__(self):
        super().__init__('SIEM Monitor', 'auto_siem')
    def _run_once(self):
        path = self.settings().get('log_path', '')
        if not path or not os.path.exists(path):
            return
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            lines = fh.readlines()[-50:]
        txt = '\n'.join(lines)
        summ = summarize('SIEM Monitor', txt) or ''
        self._emit('Summary: ' + summ)


class IPReputation(AutomationTask):
    def __init__(self):
        super().__init__('IP Reputation', 'auto_iprep')
    def _run_once(self):
        ips = self.settings().get('ips', [])
        for ip in ips:
            res = vt_ip(ip)
            self._emit(f'{ip}: ' + ('ok' if res else 'no data'))


class SuspiciousIPDetector(AutomationTask):
    def __init__(self):
        super().__init__('Suspicious IP Detector', 'auto_suspip')
    def _run_once(self):
        src = self.settings().get('source_path', '')
        if not src or not os.path.exists(src):
            return
        with open(src, 'r', encoding='utf-8', errors='ignore') as fh:
            lines = fh.readlines()[-200:]
        hits = [l.strip() for l in lines if 'failed' in l.lower() or 'denied' in l.lower()]
        if hits:
            summ = summarize('Suspicious IP Activity', '\n'.join(hits)) or ''
            self._emit('Anomalies: ' + summ)


class FileIntegrity(AutomationTask):
    def __init__(self):
        super().__init__('File Integrity Monitor', 'auto_fim')
    def _run_once(self):
        paths = self.settings().get('paths', [])
        for p in paths:
            try:
                h = file_hashes(p)
                self._emit(f'{p}: {h.get("sha256", "")}')
            except Exception:
                self._emit(f'{p}: read error')


class AutoSandbox(AutomationTask):
    def __init__(self):
        super().__init__('Auto Sandbox', 'auto_sandbox')
    def _run_once(self):
        path = self.settings().get('sample_path', '')
        if not path or not os.path.exists(path):
            return
        strings = extract_strings(path)
        iocs = extract_iocs(strings)
        self._emit('IoCs: ' + json.dumps(iocs))


class AIRisk(AutomationTask):
    def __init__(self):
        super().__init__('AI Risk Scoring', 'auto_risk')
    def _run_once(self):
        ctx = self.settings().get('context', '')
        if not ctx:
            return
        summ = summarize('Risk', ctx) or ''
        self._emit('Risk: ' + summ)


class Notifier(AutomationTask):
    def __init__(self):
        super().__init__('Notifier', 'auto_notify')
    def _run_once(self):
        msg = self.settings().get('message', '')
        if msg:
            self._emit('Notify: ' + msg)


class AutomationEngine:
    def __init__(self):
        self.tasks = {
            'siem': SIEMMonitor(),
            'iprep': IPReputation(),
            'suspip': SuspiciousIPDetector(),
            'fim': FileIntegrity(),
            'sandbox': AutoSandbox(),
            'risk': AIRisk(),
            'notify': Notifier(),
        }
    def start(self, key: str):
        t = self.tasks.get(key)
        if t:
            t.start()
    def stop(self, key: str):
        t = self.tasks.get(key)
        if t:
            t.stop()
    def logs(self, key: str):
        t = self.tasks.get(key)
        if not t:
            return []
        out = []
        try:
            while True:
                out.append(t.log_q.get_nowait())
        except Exception:
            pass
        return out
