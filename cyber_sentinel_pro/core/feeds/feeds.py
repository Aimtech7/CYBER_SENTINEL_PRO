import requests


def urlhaus_recent(limit: int = 25):
    r = requests.post('https://urlhaus.abuse.ch/api/', data={'url': 'https://urlhaus.abuse.ch/api/', 'action': 'urls', 'limit': str(limit)}, timeout=20)
    try:
        return r.json()
    except Exception:
        return None

