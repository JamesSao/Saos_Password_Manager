import os
import hmac
import hashlib
import sqlite3

from .crypto_utils import derive_raw_key

# HMAC verifier label; prevents storing the raw derived key.
_VERIF_CONST = b"pwmanager-key-check/v1"

# ---------- Connections ----------

def connect_plain(path: str) -> sqlite3.Connection:
    return sqlite3.connect(path)

def _sqlcipher_import():
    try:
        from pysqlcipher3 import dbapi2 as sqlcipher  # type: ignore
        return sqlcipher
    except Exception as e:
        raise RuntimeError("SQLCipher driver (pysqlcipher3) is not installed. Please `pip install pysqlcipher3`.") from e

def _sqlcipher_key_pragma(cursor, raw_key: bytes):
    # Use raw key (bypass SQLCipher's internal PBKDF2) for consistent strength with our Argon2id/Scrypt KDF.
    hexkey = raw_key.hex()
    cursor.execute(f"PRAGMA key = \"x'{hexkey}'\";")
    # Recommended pragmas (safe defaults)
    cursor.execute("PRAGMA cipher_memory_security = ON;")
    # Page size & algorithms can stay defaults; uncomment/tune if desired:
    # cursor.execute("PRAGMA kdf_iter = 256000;")
    # cursor.execute("PRAGMA cipher_page_size = 4096;")
    # cursor.execute("PRAGMA cipher_hmac_algorithm = HMAC_SHA512;")
    # cursor.execute("PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;")

def connect_sqlcipher(path: str, raw_key: bytes):
    sqlcipher = _sqlcipher_import()
    conn = sqlcipher.connect(path)
    cur = conn.cursor()
    _sqlcipher_key_pragma(cur, raw_key)
    # Touch the DB to verify key (will error if wrong)
    cur.execute("PRAGMA cipher_version;")
    _ = cur.fetchone()
    return conn

# ---------- sidecar salt (for SQLCipher key derivation) ----------

def sidecar_salt_path(db_path: str) -> str:
    return db_path + ".salt"

def get_or_create_sidecar_salt(db_path: str, *, salt_len: int = 32) -> bytes:
    path = sidecar_salt_path(db_path)
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
            if len(data) >= 16:
                return data
    import os as _os
    salt = _os.urandom(salt_len)
    with open(path, "wb") as f:
        f.write(salt)
    return salt

# ---------- schema helpers ----------

def ensure_passwords_table(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("""SELECT name FROM sqlite_master WHERE type='table' AND name='passwords'""")
    if not c.fetchone():
        c.execute("""CREATE TABLE passwords (website TEXT, email TEXT, password BLOB)""")
    else:
        # ensure email column exists
        c.execute("SELECT * FROM passwords")
        cols = [d[0] for d in c.description]
        if "email" not in cols:
            c.execute("ALTER TABLE passwords ADD COLUMN email TEXT")
    conn.commit()

def ensure_meta_table(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v BLOB)""")
    conn.commit()

def meta_get(conn: sqlite3.Connection, key: str):
    c = conn.cursor()
    c.execute("SELECT v FROM meta WHERE k=?", (key,))
    row = c.fetchone()
    return None if row is None else row[0]

def meta_set(conn: sqlite3.Connection, key: str, value: bytes):
    c = conn.cursor()
    c.execute("INSERT OR REPLACE INTO meta (k, v) VALUES (?, ?)", (key, value))
    conn.commit()

# ---------- Argon2id salt & verifier (for Fernet field encryption) ----------

def get_or_create_salt(conn: sqlite3.Connection, *, salt_len: int = 32) -> bytes:
    ensure_meta_table(conn)
    salt = meta_get(conn, "salt")
    if salt:
        return salt
    import os
    salt = os.urandom(salt_len)
    meta_set(conn, "salt", salt)
    return salt

def set_or_check_verifier(conn: sqlite3.Connection, key_b64: bytes) -> bool:
    """
    Store an HMAC(key, const) the first time. On subsequent opens, verify it.
    Returns True if OK, False if mismatch.
    """
    ensure_meta_table(conn)
    v = meta_get(conn, "verifier")
    mac = hmac.new(key_b64, _VERIF_CONST, hashlib.sha256).digest()
    if v is None:
        meta_set(conn, "verifier", mac)
        return True
    return hmac.compare_digest(v, mac)

# ---------- legacy support (PBKDF2 + keys table) ----------

def has_legacy_keys_table(conn: sqlite3.Connection) -> bool:
    c = conn.cursor()
    c.execute("""SELECT name FROM sqlite_master WHERE type='table' AND name='keys'""")
    return c.fetchone() is not None

def legacy_key_matches(conn: sqlite3.Connection, key_b64_str: str) -> bool:
    """
    Old scheme stored the base64 Fernet key (string) in table 'keys'.
    """
    c = conn.cursor()
    c.execute("SELECT key FROM keys")
    row = c.fetchone()
    if row is None:
        return False
    saved_key = row[0]
    return saved_key == key_b64_str

# ---------- CRUD ----------

def list_websites(conn: sqlite3.Connection):
    c = conn.cursor()
    c.execute("SELECT website FROM passwords")
    return [row[0] for row in c.fetchall()]

def insert_password(conn, website: str, enc_pw: bytes, enc_email: bytes | None):
    c = conn.cursor()
    c.execute("SELECT website FROM passwords WHERE website=?", (website,))
    if c.fetchone():
        raise ValueError("Website already exists")
    if enc_email:
        c.execute(
            "INSERT INTO passwords (website, password, email) VALUES (?, ?, ?)",
            (website, sqlite3.Binary(enc_pw), sqlite3.Binary(enc_email)),
        )
    else:
        c.execute(
            "INSERT INTO passwords (website, password) VALUES (?, ?)",
            (website, sqlite3.Binary(enc_pw)),
        )
    conn.commit()

def get_credentials(conn, website: str):
    c = conn.cursor()
    c.execute("SELECT password, email FROM passwords WHERE website=?", (website,))
    return c.fetchone()

def delete_website(conn, website: str):
    c = conn.cursor()
    c.execute("DELETE FROM passwords WHERE website=?", (website,))
    conn.commit()

def delete_all_rows(conn):
    c = conn.cursor()
    c.execute("DELETE FROM passwords")
    conn.commit()

# ---------- helpers for SQLCipher open ----------

def open_sqlcipher_with_master(master_key: str, db_path: str):
    """
    Create/read sidecar salt and open an SQLCipher-encrypted DB using a raw key
    derived via Argon2id/Scrypt from (master_key, sidecar_salt).
    Returns (conn, raw_key, sidecar_salt).
    """
    salt = get_or_create_sidecar_salt(db_path)
    raw_key = derive_raw_key(master_key, salt)
    conn = connect_sqlcipher(db_path, raw_key)
    return conn, raw_key, salt
