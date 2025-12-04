import requests
from typing import Dict, Optional
from core.utils.secure_storage import load_secret


def vt_headers():
    key = load_secret('virustotal_api_key')
    return {'x-apikey': key} if key else None


def vt_ip(ip: str) -> Optional[Dict]:
    h = vt_headers()
    if not h:
        return None
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    r = requests.get(url, headers=h, timeout=20)
    return r.json()


def vt_domain(domain: str) -> Optional[Dict]:
    h = vt_headers()
    if not h:
        return None
    url = f'https://www.virustotal.com/api/v3/domains/{domain}'
    r = requests.get(url, headers=h, timeout=20)
    return r.json()


def vt_url(url_s: str) -> Optional[Dict]:
    h = vt_headers()
    if not h:
        return None
    url = 'https://www.virustotal.com/api/v3/urls'
    r = requests.post(url, headers=h, data={'url': url_s}, timeout=20)
    if r.status_code == 200:
        data_id = r.json()['data']['id']
        r2 = requests.get(f'https://www.virustotal.com/api/v3/analyses/{data_id}', headers=h, timeout=20)
        return r2.json()
    return r.json()


def vt_file(hash_val: str) -> Optional[Dict]:
    h = vt_headers()
    if not h:
        return None
    url = f'https://www.virustotal.com/api/v3/files/{hash_val}'
    r = requests.get(url, headers=h, timeout=20)
    return r.json()


def shodan_ip(ip: str) -> Optional[Dict]:
    key = load_secret('shodan_api_key')
    if not key:
        return None
    url = f'https://api.shodan.io/shodan/host/{ip}?key={key}'
    r = requests.get(url, timeout=20)
    return r.json()


def abuseipdb_ip(ip: str) -> Optional[Dict]:
    key = load_secret('abuseipdb_api_key')
    if not key:
        return None
    url = 'https://api.abuseipdb.com/api/v2/check'
    r = requests.get(url, params={'ipAddress': ip, 'maxAgeInDays': 90}, headers={'Key': key, 'Accept': 'application/json'}, timeout=20)
    return r.json()


def otx_general(ioc_type: str, value: str) -> Optional[Dict]:
    key = load_secret('otx_api_key')
    headers = {'X-OTX-API-KEY': key} if key else {}
    url = f'https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{value}/general'
    try:
        r = requests.get(url, headers=headers, timeout=20)
        return r.json()
    except Exception:
        return None
