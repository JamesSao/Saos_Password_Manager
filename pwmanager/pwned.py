import hashlib
import requests

def _get_password_leak_count(hashes_text: str, hash_to_check: str) -> int:
    for line in hashes_text.splitlines():
        if not line:
            continue
        h, count = line.split(":")
        if h == hash_to_check:
            return int(count)
    return 0

def pwned_api_check(password: str) -> int:
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5, tail = sha1password[:5], sha1password[5:]
    resp = requests.get(f"https://api.pwnedpasswords.com/range/{first5}")
    if resp.status_code != 200:
        raise RuntimeError(f"Error fetching: {resp.status_code}, check the API and try again")
    return _get_password_leak_count(resp.text, tail)
