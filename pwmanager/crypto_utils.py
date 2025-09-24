import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# Legacy PBKDF2 (kept for backward compatibility)
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Optional strong KDFs
try:
    # Preferred path: Argon2id (needs argon2-cffi)
    from argon2.low_level import hash_secret_raw, Type as Argon2Type  # type: ignore
    _HAS_ARGON2 = True
except Exception:
    _HAS_ARGON2 = False

try:
    # Fallback path: Scrypt (ships with cryptography)
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    _HAS_SCRYPT = True
except Exception:
    _HAS_SCRYPT = False

# ---- Legacy PBKDF2 settings (unchanged) ----
_LEGACY_SALT = b"B+G66/pl?wOlYLP7wxCCjCfLL>/Xn74:ABix4!"
_LEGACY_SUFFIX = b".M7XRxa2QNnE>/PjKYNCJKDHY7KXDfcFxp?k("

def derive_fernet_pbkdf2(master_key: str):
    """
    Legacy derivation: PBKDF2-HMAC-SHA256 with static salt/suffix, 100k iterations.
    Returns (fernet, key_b64).
    """
    bmaster_key = master_key.encode("utf-8")
    password = bmaster_key + _LEGACY_SUFFIX
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=_LEGACY_SALT,
        iterations=100000,
        backend=default_backend(),
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key), key

# ---------- Strong KDFs (Argon2id preferred, Scrypt fallback) ----------

def _derive_raw_argon2id(master_key: str, salt: bytes, *, time_cost=3, memory_cost_mib=256, parallelism=2) -> bytes:
    key_raw = hash_secret_raw(
        secret=master_key.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost_mib * 1024,  # KiB
        parallelism=parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )
    return key_raw

def _derive_raw_scrypt(master_key: str, salt: bytes, *, n=2**15, r=8, p=2) -> bytes:
    """
    Scrypt fallback: memory-hard and widely available via cryptography.
    n=2**15 (~32 MiB), r=8, p=2 are good desktop defaults.
    """
    if not _HAS_SCRYPT:
        raise RuntimeError("Scrypt KDF is unavailable in this environment.")
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(master_key.encode("utf-8"))

def derive_raw_key(master_key: str, salt: bytes, *, time_cost=3, memory_cost_mib=256, parallelism=2) -> bytes:
    """
    Returns 32 raw key bytes using Argon2id if available, else Scrypt.
    Suitable as a raw key for SQLCipher.
    """
    if _HAS_ARGON2:
        return _derive_raw_argon2id(master_key, salt, time_cost=time_cost, memory_cost_mib=memory_cost_mib, parallelism=parallelism)
    return _derive_raw_scrypt(master_key, salt, n=2**15, r=8, p=parallelism)

def derive_fernet_argon2id(master_key: str, salt: bytes, *, time_cost=3, memory_cost_mib=256, parallelism=2):
    """
    Strong derivation used by the app for Fernet encryption of fields.
    Tries Argon2id first; if argon2-cffi isn't installed, falls back to Scrypt.
    Returns (fernet, key_b64).
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) < 16:
        raise ValueError("Salt must be bytes and >= 16 bytes long")
    key_raw = derive_raw_key(master_key, salt, time_cost=time_cost, memory_cost_mib=memory_cost_mib, parallelism=parallelism)
    key_b64 = base64.urlsafe_b64encode(key_raw)
    return Fernet(key_b64), key_b64

def encrypt_str(f: Fernet, s: str) -> bytes:
    return f.encrypt(s.encode())

def decrypt_str(f: Fernet, b: bytes) -> str:
    return f.decrypt(b).decode()
