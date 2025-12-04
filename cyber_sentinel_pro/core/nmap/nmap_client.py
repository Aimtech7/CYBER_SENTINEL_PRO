from typing import Dict, List
import nmap


class NmapClient:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target: str, profile: str) -> Dict:
        if profile == 'quick':
            args = '-T4 -F'
        elif profile == 'intense':
            args = '-T4 -A -v'
        else:
            args = '-p- -sV -O'
        res = self.nm.scan(target, arguments=args)
        return res

    def parse(self, res: Dict) -> List[Dict]:
        out = []
        for host, hdata in res.get('scan', {}).items():
            tcp = hdata.get('tcp', {})
            for port, pdata in tcp.items():
                out.append({
                    'host': host,
                    'port': port,
                    'state': pdata.get('state'),
                    'name': pdata.get('name'),
                    'product': pdata.get('product'),
                    'version': pdata.get('version'),
                })
        return out

