import json
from typing import List, Dict


def parse_eve_json(lines: List[str]) -> Dict:
    alerts = []
    sig_counts = {}
    sev_counts = {}
    for ln in lines:
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        if obj.get('event_type') == 'alert':
            a = obj.get('alert', {})
            sig = a.get('signature') or 'unknown'
            sev = a.get('severity') or 0
            alerts.append({
                'timestamp': obj.get('timestamp'),
                'src_ip': obj.get('src_ip'),
                'dest_ip': obj.get('dest_ip'),
                'signature': sig,
                'severity': sev,
            })
            sig_counts[sig] = sig_counts.get(sig, 0) + 1
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
    return {'alerts': alerts, 'sig_counts': sig_counts, 'sev_counts': sev_counts}

