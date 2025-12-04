import requests
from core.utils.secure_storage import load_secret


def urlhaus_recent(limit: int = 25):
    r = requests.post('https://urlhaus.abuse.ch/api/', data={'url': 'https://urlhaus.abuse.ch/api/', 'action': 'urls', 'limit': str(limit)}, timeout=20)
    try:
        return r.json()
    except Exception:
        return None


def otx_general(ioc_type: str, value: str):
    base = 'https://otx.alienvault.com/api/v1/indicators'
    url = f'{base}/{ioc_type}/{value}/general'
    headers = {}
    key = load_secret('otx_api_key')
    if key:
        headers['X-OTX-API-KEY'] = key
    try:
        r = requests.get(url, headers=headers, timeout=20)
        return r.json()
    except Exception:
        return None
