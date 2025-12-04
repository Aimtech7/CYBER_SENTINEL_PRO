import platform
import subprocess
import shutil
from typing import List, Dict, Optional
import re

try:
    import pywifi
    from pywifi import const
except Exception:
    pywifi = None
    const = None


def list_interfaces() -> List[str]:
    if pywifi:
        wifi = pywifi.PyWiFi()
        return [i.name() for i in wifi.interfaces()]
    # Fallback on Windows using netsh
    if platform.system() == 'Windows':
        try:
            out = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True, errors='ignore')
            names = []
            for line in out.splitlines():
                if 'Name' in line and ':' in line:
                    names.append(line.split(':', 1)[1].strip())
            return names
        except Exception:
            return []
    return []


def scan_networks(interface_name: Optional[str] = None) -> List[Dict]:
    results = []
    if pywifi:
        wifi = pywifi.PyWiFi()
        iface = None
        for i in wifi.interfaces():
            if not interface_name or i.name() == interface_name:
                iface = i
                break
        if not iface:
            return []
        iface.scan()
        import time
        time.sleep(2)
        def freq_to_channel(freq: int) -> Optional[int]:
            try:
                if 2400 < freq < 2500:
                    ch = int(round((freq - 2407) / 5))
                    return ch if 1 <= ch <= 14 else None
                if 5000 < freq < 6000:
                    # rough 5GHz mapping
                    return int((freq - 5000) / 5)
            except Exception:
                return None
            return None
        for p in iface.scan_results():
            chan = None
            try:
                chan = freq_to_channel(getattr(p, 'freq', 0) or 0)
            except Exception:
                chan = None
            results.append({
                'ssid': getattr(p, 'ssid', '') or '',
                'bssid': getattr(p, 'bssid', '') or '',
                'signal': getattr(p, 'signal', 0) or 0,
                'auth': getattr(p, 'akm', None),
                'cipher': getattr(p, 'cipher', None),
                'channel': chan,
            })
        return results

    # Fallback via netsh on Windows
    if platform.system() == 'Windows':
        try:
            out = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], text=True, errors='ignore')
            ssid = ''
            bssid = ''
            signal = ''
            auth = ''
            cipher = ''
            channel = None
            for line in out.splitlines():
                line = line.strip()
                if line.startswith('SSID'):
                    ssid = line.split(':', 1)[1].strip()
                elif line.startswith('BSSID'):
                    bssid = line.split(':', 1)[1].strip()
                elif line.startswith('Signal'):
                    signal = line.split(':', 1)[1].strip()
                    try:
                        s = int(signal.replace('%', '').strip())
                    except Exception:
                        s = 0
                    results.append({'ssid': ssid, 'bssid': bssid, 'signal': s, 'auth': auth or None, 'cipher': cipher or None, 'channel': channel})
                elif line.startswith('Authentication'):
                    auth = line.split(':', 1)[1].strip()
                elif line.startswith('Encryption'):
                    cipher = line.split(':', 1)[1].strip()
                elif line.startswith('Channel'):
                    try:
                        channel = int(line.split(':', 1)[1].strip())
                    except Exception:
                        channel = None
            return results
        except Exception:
            return []
    return []


def has_aircrack_tools() -> bool:
    for tool in ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng']:
        if shutil.which(tool):
            return True
    # WSL detection: try 'wsl which'
    if platform.system() == 'Windows' and shutil.which('wsl'):
        try:
            out = subprocess.run(['wsl', 'which', 'aircrack-ng'], capture_output=True)
            if out.returncode == 0:
                return True
        except Exception:
            pass
    return False


def get_interface_gateway(interface_name: Optional[str]) -> Optional[str]:
    if platform.system() == 'Windows':
        try:
            if not interface_name:
                # try to find active wifi interface
                out = subprocess.check_output(['netsh', 'wlan', 'show', 'interfaces'], text=True, errors='ignore')
                m = re.search(r'^\s*Name\s*:\s*(.+)$', out, re.MULTILINE)
                if m:
                    interface_name = m.group(1).strip()
            if not interface_name:
                return None
            out = subprocess.check_output(['netsh', 'interface', 'ip', 'show', 'config', f'name={interface_name}'], text=True, errors='ignore')
            m = re.search(r'Default Gateway\s*:\s*([^\r\n]+)', out)
            if m:
                gw = m.group(1).strip()
                return gw if gw and gw.lower() != 'none' else None
            return None
        except Exception:
            return None
    # non-Windows: try ip route
    try:
        out = subprocess.check_output(['ip', 'route'], text=True, errors='ignore')
        for ln in out.splitlines():
            if ln.startswith('default'):
                parts = ln.split()
                for i, p in enumerate(parts):
                    if p == 'via' and i + 1 < len(parts):
                        return parts[i + 1]
        return None
    except Exception:
        return None
