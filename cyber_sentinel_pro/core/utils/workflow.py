import time
import json
from apscheduler.schedulers.background import BackgroundScheduler
from core.utils.secure_storage import save_setting, load_setting
from core.utils.ai_client import probe
from core.threatintel.apis import vt_domain, shodan_ip, abuseipdb_ip


def _self_test_once():
    res = {}
    ok_ai, msg_ai = probe()
    res['openai'] = msg_ai
    try:
        vt = vt_domain('example.com'); res['virustotal'] = 'ok' if vt and 'data' in vt else 'no'
    except Exception:
        res['virustotal'] = 'err'
    try:
        sh = shodan_ip('8.8.8.8'); res['shodan'] = 'ok' if sh and ('ip_str' in sh or 'data' in sh) else 'no'
    except Exception:
        res['shodan'] = 'err'
    try:
        ab = abuseipdb_ip('1.1.1.1'); res['abuseipdb'] = 'ok' if ab and ('data' in ab) else 'no'
    except Exception:
        res['abuseipdb'] = 'err'
    res['ts'] = time.time()
    log = load_setting('self_test_log', []) or []
    log.append(res)
    save_setting('self_test_log', log)


_SCHED = None


def schedule_self_test():
    global _SCHED
    if _SCHED:
        return _SCHED
    s = BackgroundScheduler()
    s.add_job(_self_test_once, 'interval', hours=6, next_run_time=None)
    s.start()
    _SCHED = s
    return s
