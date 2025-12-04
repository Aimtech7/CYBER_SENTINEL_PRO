import math
import hashlib
import requests


def entropy(password: str) -> float:
    charset = 0
    if any(c.islower() for c in password):
        charset += 26
    if any(c.isupper() for c in password):
        charset += 26
    if any(c.isdigit() for c in password):
        charset += 10
    if any(c in '!@#$%^&*()-_=+[]{};:\",.<>/?' for c in password):
        charset += 32
    if charset == 0:
        return 0.0
    return math.log(charset, 2) * len(password)


def policy_check(password: str) -> dict:
    return {
        'len_ok': len(password) >= 12,
        'has_upper': any(c.isupper() for c in password),
        'has_lower': any(c.islower() for c in password),
        'has_digit': any(c.isdigit() for c in password),
        'has_symbol': any(c in '!@#$%^&*()-_=+[]{};:\",.<>/?' for c in password),
    }


def hibp_pwned(password: str) -> int:
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=15)
    if r.status_code != 200:
        return -1
    for line in r.text.splitlines():
        if ':' not in line:
            continue
        s, count = line.split(':')
        if s == suffix:
            return int(count)
    return 0

