from typing import Callable, Optional, List
from dataclasses import dataclass
import time

try:
    from scapy.all import sniff, wrpcap, Packet
except Exception:
    sniff = None
    wrpcap = None
    Packet = object


@dataclass
class Captured:
    ts: float
    proto: str
    src: str
    dst: str
    length: int
    raw: bytes


class Sniffer:
    def __init__(self, iface: Optional[str] = None, bpf: Optional[str] = None):
        self.iface = iface
        self.bpf = bpf
        self._packets: List[Packet] = []
        self._records: List[Captured] = []

    def _proto(self, p: Packet) -> str:
        try:
            if p.haslayer('TCP'):
                return 'TCP'
            if p.haslayer('UDP'):
                return 'UDP'
            if p.haslayer('DNS'):
                return 'DNS'
            if p.haslayer('ARP'):
                return 'ARP'
            if p.haslayer('HTTP'):
                return 'HTTP'
        except Exception:
            pass
        return 'OTHER'

    def _src(self, p: Packet) -> str:
        try:
            if p.haslayer('IP'):
                return p['IP'].src
            if p.haslayer('ARP'):
                return p['ARP'].psrc
        except Exception:
            pass
        return ''

    def _dst(self, p: Packet) -> str:
        try:
            if p.haslayer('IP'):
                return p['IP'].dst
            if p.haslayer('ARP'):
                return p['ARP'].pdst
        except Exception:
            pass
        return ''

    def start(self, on_packet: Callable[[Captured], None], stop_flag: Callable[[], bool]):
        if sniff is None:
            raise RuntimeError('Scapy is not available. Install scapy and Npcap (Windows).')

        def _cb(pkt: Packet):
            raw = bytes(pkt)
            cap = Captured(
                ts=time.time(),
                proto=self._proto(pkt),
                src=self._src(pkt),
                dst=self._dst(pkt),
                length=len(raw),
                raw=raw,
            )
            self._packets.append(pkt)
            self._records.append(cap)
            on_packet(cap)

        sniff(iface=self.iface, filter=self.bpf, prn=_cb, store=False, stop_filter=lambda _: stop_flag())

    def export_pcap(self, path: str):
        if wrpcap is None:
            raise RuntimeError('Scapy/wrpcap not available')
        wrpcap(path, self._packets)

    def stats(self):
        return self._records

