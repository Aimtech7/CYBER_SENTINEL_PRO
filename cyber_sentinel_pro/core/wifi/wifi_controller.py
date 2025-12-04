import platform
import subprocess
import shutil
from typing import List, Dict, Optional

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
        for p in iface.scan_results():
            results.append({
                'ssid': p.ssid,
                'bssid': p.bssid,
                'signal': p.signal,
                'auth': p.akm,
                'cipher': p.cipher,
            })
        return results

    # Fallback via netsh on Windows
    if platform.system() == 'Windows':
        try:
            out = subprocess.check_output(['netsh', 'wlan', 'show', 'networks', 'mode=Bssid'], text=True, errors='ignore')
            ssid = ''
            bssid = ''
            signal = ''
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
                    results.append({'ssid': ssid, 'bssid': bssid, 'signal': s, 'auth': None, 'cipher': None})
            return results
        except Exception:
            return []
    return []


def has_aircrack_tools() -> bool:
    for tool in ['airmon-ng', 'airodump-ng', 'aireplay-ng', 'aircrack-ng']:
        if shutil.which(tool):
            return True
    # Users may use WSL; attempt detection
    return False

