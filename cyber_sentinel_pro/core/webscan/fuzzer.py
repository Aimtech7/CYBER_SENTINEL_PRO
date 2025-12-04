import requests
from typing import List, Dict


DEFAULT_PAYLOADS = [
    "' OR '1'='1",
    '<script>alert(1)</script>',
    '../../etc/passwd',
    '" onclick="alert(1)"',
]


def fuzz(url: str, param: str, payloads: List[str] = None, timeout: int = 10) -> List[Dict]:
    out = []
    payloads = payloads or DEFAULT_PAYLOADS
    s = requests.Session()
    for p in payloads:
        try:
            r = s.get(url, params={param: p}, timeout=timeout)
            hit = False
            if p in r.text:
                hit = True
            if 'sql' in p.lower() and 'error' in r.text.lower():
                hit = True
            out.append({'payload': p, 'status': r.status_code, 'length': len(r.text), 'reflected': hit})
        except Exception as e:
            out.append({'payload': p, 'error': str(e)})
    return out

