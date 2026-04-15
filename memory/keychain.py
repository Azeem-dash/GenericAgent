"""Keychain: save key to a file, then keys.set("name", file="path"); keys.name.use() to retrieve (use but no print)."""
import json, os, hashlib, pathlib, base64

from cryptography.fernet import Fernet, InvalidToken

_PATH = pathlib.Path.home() / "ga_keychain.enc"
_SALT_PATH = pathlib.Path.home() / "ga_keychain.salt"

def _get_or_create_salt() -> bytes:
    """Return a persistent per-installation random salt, creating it on first use."""
    if _SALT_PATH.exists():
        return _SALT_PATH.read_bytes()
    salt = os.urandom(16)
    _SALT_PATH.write_bytes(salt)
    return salt

def _derive_fernet_key() -> bytes:
    """Derive a Fernet key from user identity + per-installation random salt using PBKDF2."""
    try:
        user = os.getlogin()
    except OSError:
        import getpass
        user = getpass.getuser()
    identity = f"{user}@ga_keychain".encode()
    salt = _get_or_create_salt()
    dk = hashlib.pbkdf2_hmac("sha256", identity, salt, iterations=200_000)
    return base64.urlsafe_b64encode(dk)

_FERNET = Fernet(_derive_fernet_key())

# Legacy XOR used only for transparent one-time migration of old keychain files.
def _xor_legacy(data: bytes) -> bytes:
    try:
        user = os.getlogin()
    except OSError:
        import getpass
        user = getpass.getuser()
    mask = hashlib.sha256(f"{user}@ga_keychain".encode()).digest()
    return bytes(b ^ mask[i % len(mask)] for i, b in enumerate(data))


class SecretStr:
    def __init__(self, name: str, val: str):
        self._name, self._val = name, val
    def use(self) -> str:
        return self._val
    def __repr__(self):
        n = len(self._val)
        if n <= 4:     preview = '***'
        elif n <= 16:  preview = f"{self._val[:3]}···{self._val[-3:]}"
        elif n <= 40:  preview = f"{self._val[:6]}···{self._val[-6:]} len={n}"
        else:          preview = f"{self._val[:10]}···{self._val[-6:]} len={n}"
        return f"SecretStr({self._name}={preview}) # .use() to get raw, do not print raw value"
    __str__ = __repr__

class _Keys:
    def __init__(self):
        self._d = {}
        if _PATH.exists():
            raw = _PATH.read_bytes()
            # Try Fernet (v2) decryption first; fall back to legacy XOR for migration.
            try:
                self._d = json.loads(_FERNET.decrypt(raw))
            except (InvalidToken, Exception):
                try:
                    self._d = json.loads(_xor_legacy(raw))
                    # Re-encrypt with Fernet and overwrite the legacy file.
                    _PATH.write_bytes(_FERNET.encrypt(json.dumps(self._d).encode()))
                    print("[keychain] Migrated keychain to Fernet encryption.")
                except Exception as e:
                    print(f"[keychain] WARNING: failed to load {_PATH}: {e}")
                    print(f"[keychain] Starting with empty keychain. Old file kept as .bak")
                    _PATH.rename(_PATH.with_suffix('.enc.bak'))
    def __getattr__(self, k):
        if k.startswith('_'): raise AttributeError(k)
        if k not in self._d: raise KeyError(f"No secret: {k}")
        return SecretStr(k, self._d[k])
    def set(self, k, v=None, *, file=None):
        if file: v = pathlib.Path(file).read_text().strip()
        self._d[k] = v
        _PATH.write_bytes(_FERNET.encrypt(json.dumps(self._d).encode()))
    def ls(self): return list(self._d.keys())

keys = _Keys()

def __getattr__(name): return getattr(keys, name)
