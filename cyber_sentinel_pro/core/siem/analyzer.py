import re
from typing import List, Dict, Tuple
from collections import Counter


LOG_PATTERNS = {
    'apache_access': re.compile(r'\d+\.\d+\.\d+\.\d+ - - \[[^\]]+\] "(GET|POST) ([^ ]+) [^"]+" (\d{3})'),
    'nginx_access': re.compile(r'\d+\.\d+\.\d+\.\d+ - - \[[^\]]+\] "(GET|POST) ([^ ]+) [^"]+" (\d{3})'),
    'syslog_auth': re.compile(r'Failed password for'),
}


def parse_lines(lines: List[str]) -> Dict:
    findings: List[Dict] = []
    status_counter = Counter()
    uri_counter = Counter()
    auth_fail = 0
    for ln in lines:
        m = LOG_PATTERNS['apache_access'].search(ln) or LOG_PATTERNS['nginx_access'].search(ln)
        if m:
            method, uri, status = m.groups()
            status_counter[status] += 1
            uri_counter[uri] += 1
            if status.startswith('4') or status.startswith('5'):
                findings.append({'type': 'http_error', 'detail': f'{method} {uri} {status}'})
        if LOG_PATTERNS['syslog_auth'].search(ln):
            auth_fail += 1
    return {
        'findings': findings,
        'status_counts': dict(status_counter),
        'top_uris': uri_counter.most_common(10),
        'auth_failures': auth_fail,
    }

