import os
import json
import base64
import getpass
import hashlib
from typing import Optional

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


APP_DIR = os.path.join(os.path.expanduser('~'), '.cyber_sentinel_pro')
SETTINGS_PATH = os.path.join(APP_DIR, 'settings.json')
BACKUP_PATH = os.path.join(APP_DIR, 'settings.bak')


def _ensure_app_dir():
    if not os.path.exists(APP_DIR):
        os.makedirs(APP_DIR, exist_ok=True)


def _derive_key() -> bytes:
    user = getpass.getuser().encode()
    node = str(hash(os.getenv('COMPUTERNAME', 'unknown'))).encode()
    salt = hashlib.sha256(user + node).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(user + node))


def _get_fernet() -> Fernet:
    return Fernet(_derive_key())


def _atomic_write(path: str, data: dict) -> None:
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, path)
    try:
        with open(BACKUP_PATH, 'w', encoding='utf-8') as fh:
            json.dump(data, fh, indent=2)
    except Exception:
        pass


def save_secret(name: str, value: str) -> None:
    _ensure_app_dir()
    f = _get_fernet()
    token = f.encrypt((value or '').encode())
    data = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            data = {}
    data[name] = token.decode()
    _atomic_write(SETTINGS_PATH, data)


def load_secret(name: str) -> Optional[str]:
    if not os.path.exists(SETTINGS_PATH):
        # fallback to backup
        if os.path.exists(BACKUP_PATH):
            try:
                with open(BACKUP_PATH, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                enc = data.get(name)
                if enc:
                    f = _get_fernet()
                    return f.decrypt(enc.encode()).decode()
            except Exception:
                pass
        return None
    try:
        with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        enc = data.get(name)
        if not enc:
            return None
        f = _get_fernet()
        return f.decrypt(enc.encode()).decode()
    except Exception:
        # try backup
        try:
            with open(BACKUP_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            enc = data.get(name)
            if not enc:
                return None
            f = _get_fernet()
            return f.decrypt(enc.encode()).decode()
        except Exception:
            return None


def save_setting(name: str, value):
    _ensure_app_dir()
    data = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            data = {}
    data[name] = value
    _atomic_write(SETTINGS_PATH, data)


def load_setting(name: str, default=None):
    if not os.path.exists(SETTINGS_PATH):
        # fallback to backup
        if os.path.exists(BACKUP_PATH):
            try:
                with open(BACKUP_PATH, 'r', encoding='utf-8') as fh:
                    data = json.load(fh)
                return data.get(name, default)
            except Exception:
                return default
        return default
    try:
        with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        return data.get(name, default)
    except Exception:
        # try backup
        try:
            with open(BACKUP_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            return data.get(name, default)
        except Exception:
            return default


def save_multiple_secrets(payload: dict) -> None:
    _ensure_app_dir()
    f = _get_fernet()
    data = {}
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
        except Exception:
            data = {}
    for k, v in payload.items():
        data[k] = f.encrypt((v or '').encode()).decode()
    _atomic_write(SETTINGS_PATH, data)
