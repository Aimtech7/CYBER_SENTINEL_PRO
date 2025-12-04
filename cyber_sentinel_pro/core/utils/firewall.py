import sys
import subprocess
from typing import List
from core.utils.secure_storage import load_setting, save_setting


def _run(cmd: List[str]) -> bool:
    try:
        subprocess.run(cmd, check=True, capture_output=True)
        return True
    except Exception:
        return False


def block_ip(ip: str) -> bool:
    if sys.platform.startswith('win'):
        name = f'CyberSentinelBlock_{ip}'
        ok = _run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name='+name, 'dir=out', 'action=block', 'remoteip='+ip])
        if ok:
            _history_add(ip, 'block')
        return ok
    ok = _run(['which', 'ufw'])
    if ok:
        res = _run(['sudo', 'ufw', 'deny', 'out', 'to', ip])
    else:
        res = _run(['sudo', 'iptables', '-A', 'OUTPUT', '-d', ip, '-j', 'DROP'])
    if res:
        _history_add(ip, 'block')
    return res


def unblock_ip(ip: str) -> bool:
    if sys.platform.startswith('win'):
        name = f'CyberSentinelBlock_{ip}'
        ok = _run(['netsh', 'advfirewall', 'firewall', 'delete', 'rule', 'name='+name])
        if ok:
            _history_add(ip, 'unblock')
        return ok
    ok = _run(['which', 'ufw'])
    if ok:
        res = _run(['sudo', 'ufw', 'allow', 'out', 'to', ip])
    else:
        res = _run(['sudo', 'iptables', '-D', 'OUTPUT', '-d', ip, '-j', 'DROP'])
    if res:
        _history_add(ip, 'unblock')
    return res


def _history_add(ip: str, action: str):
    hist = load_setting('firewall_history', []) or []
    hist.append({'ip': ip, 'action': action})
    save_setting('firewall_history', hist)


def history():
    return load_setting('firewall_history', []) or []
