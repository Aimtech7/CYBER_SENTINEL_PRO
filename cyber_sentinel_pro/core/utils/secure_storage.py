import os
import json
import base64
import getpass
import hashlib
import platform
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


def _derive_key_v2() -> bytes:
    user = getpass.getuser().encode()
    node = (platform.node() or os.getenv('COMPUTERNAME', 'unknown')).encode()
    profile = load_setting('profile_name', '')
    profile_b = (profile or '').encode()
    salt = hashlib.sha256(user + node + profile_b).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(user + node + profile_b))


def _derive_key_v1_legacy() -> bytes:
    user = getpass.getuser().encode()
    # Legacy used Python's hash(), which is randomized per process; keep for migration
    node = str(hash(os.getenv('COMPUTERNAME', 'unknown'))).encode()
    salt = hashlib.sha256(user + node).digest()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000, backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(user + node))


def _get_fernet_v2() -> Fernet:
    return Fernet(_derive_key_v2())


def _get_fernet_v1() -> Fernet:
    return Fernet(_derive_key_v1_legacy())


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
    f = _get_fernet_v2()
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
                    # Try v2, then legacy v1
                    try:
                        f2 = _get_fernet_v2()
                        return f2.decrypt(enc.encode()).decode()
                    except Exception:
                        try:
                            f1 = _get_fernet_v1()
                            plain = f1.decrypt(enc.encode()).decode()
                            # migrate backup to v2
                            data[name] = _get_fernet_v2().encrypt(plain.encode()).decode()
                            _atomic_write(BACKUP_PATH, data)
                            return plain
                        except Exception:
                            return None
            except Exception:
                pass
        return None
    try:
        with open(SETTINGS_PATH, 'r', encoding='utf-8') as fh:
            data = json.load(fh)
        enc = data.get(name)
        if not enc:
            return None
        # Try v2, then legacy v1 and migrate
        try:
            f2 = _get_fernet_v2()
            return f2.decrypt(enc.encode()).decode()
        except Exception:
            try:
                f1 = _get_fernet_v1()
                plain = f1.decrypt(enc.encode()).decode()
                # migrate to v2
                data[name] = _get_fernet_v2().encrypt(plain.encode()).decode()
                _atomic_write(SETTINGS_PATH, data)
                return plain
            except Exception:
                pass
    except Exception:
        # try backup
        try:
            with open(BACKUP_PATH, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            enc = data.get(name)
            if not enc:
                return None
            try:
                f2 = _get_fernet_v2()
                return f2.decrypt(enc.encode()).decode()
            except Exception:
                try:
                    f1 = _get_fernet_v1()
                    plain = f1.decrypt(enc.encode()).decode()
                    data[name] = _get_fernet_v2().encrypt(plain.encode()).decode()
                    _atomic_write(BACKUP_PATH, data)
                    return plain
                except Exception:
                    return None
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
