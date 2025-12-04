import re
import os
import time
from typing import List, Dict, Set
import requests
from bs4 import BeautifulSoup
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

SQL_ERRORS = [
    'you have an error in your sql syntax',
    'warning: mysql',
    'unclosed quotation mark after the character string',
    'postgresql',
]


class WebScanner:
    def __init__(self, base_url: str, timeout: int = 10):
        self.base = base_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.findings: List[Dict] = []
        self.crawled: Set[str] = set()

    def _record(self, kind: str, url: str, detail: str):
        self.findings.append({'type': kind, 'url': url, 'detail': detail, 'ts': time.time()})

    def crawler(self, max_pages: int = 50):
        frontier = [self.base]
        while frontier and len(self.crawled) < max_pages:
            url = frontier.pop(0)
            if url in self.crawled:
                continue
            try:
                r = self.session.get(url, timeout=self.timeout)
                self.crawled.add(url)
                soup = BeautifulSoup(r.text, 'html.parser')
                for a in soup.find_all('a'):
                    href = a.get('href')
                    if not href:
                        continue
                    if href.startswith('http'):
                        if href.startswith(self.base):
                            frontier.append(href)
                    elif href.startswith('/'):
                        frontier.append(self.base + href)
            except Exception:
                self._record('crawler_error', url, 'Failed to fetch')

    def test_sql_injection(self, url: str):
        try:
            r = self.session.get(url + "%' OR '1'='1", timeout=self.timeout)
            text = r.text.lower()
            for e in SQL_ERRORS:
                if e in text:
                    self._record('sql_injection', url, 'Error signature detected')
                    return
        except Exception:
            self._record('sql_injection_error', url, 'Request failed')

    def test_xss(self, url: str):
        payload = '<script>alert(1)</script>'
        try:
            r = self.session.get(url + f'?x={requests.utils.quote(payload)}', timeout=self.timeout)
            if payload in r.text:
                self._record('xss_reflected', url, 'Reflected payload detected')
        except Exception:
            self._record('xss_error', url, 'Request failed')

    def dir_bruteforce(self, paths: List[str]):
        for p in paths:
            url = f'{self.base}/{p.strip().lstrip("/")}'
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code in (200, 301, 302):
                    self._record('dir_found', url, f'Status {r.status_code}')
            except Exception:
                self._record('dir_error', url, 'Request failed')

    def export_html(self, path: str):
        lines = ['<html><head><title>WebScan Report</title></head><body>', '<h1>WebScan Report</h1>', '<ul>']
        for f in self.findings:
            lines.append(f"<li><b>{f['type']}</b> - {f['url']} - {f['detail']}</li>")
        lines.extend(['</ul>', '</body></html>'])
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write('\n'.join(lines))

    def export_pdf(self, path: str):
        c = canvas.Canvas(path, pagesize=letter)
        c.setFont('Helvetica', 12)
        c.drawString(50, 750, 'Web Vulnerability Scan Report')
        y = 720
        for f in self.findings:
            s = f"{f['type']} - {f['url']} - {f['detail']}"
            c.drawString(50, y, s[:100])
            y -= 20
            if y < 80:
                c.showPage(); y = 750
        c.save()

