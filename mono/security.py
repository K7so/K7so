"""口令哈希、会话签名与密钥加密。全部基于标准库 + cryptography.Fernet。"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .config import SECRET_PATH, SESSION_TTL, ensure_dirs

_PBKDF2_ITERATIONS = 200_000


def _master_key() -> bytes:
    ensure_dirs()
    if not SECRET_PATH.exists():
        SECRET_PATH.write_bytes(Fernet.generate_key())
    return SECRET_PATH.read_bytes().strip()


def encrypt_secret(value: str) -> str:
    if not value:
        return ""
    return Fernet(_master_key()).encrypt(value.encode()).decode()


def decrypt_secret(value: str) -> str:
    if not value:
        return ""
    try:
        return Fernet(_master_key()).decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        return ""


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"pbkdf2${_PBKDF2_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations, salt, digest = stored.split("$", 3)
    except ValueError:
        return False
    if scheme != "pbkdf2":
        return False
    calculated = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), int(iterations))
    return hmac.compare_digest(calculated.hex(), digest)


def _session_key() -> bytes:
    return hmac.new(_master_key(), b"mono-session-signing", hashlib.sha256).digest()


def create_session(username: str, role: str, ttl: int = SESSION_TTL) -> str:
    payload = {"u": username, "r": role, "exp": int(time.time()) + ttl}
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(_session_key(), raw.encode(), hashlib.sha256).hexdigest()
    return f"{raw}.{signature}"


def read_session(token: str | None) -> dict[str, Any] | None:
    if not token or "." not in token:
        return None
    raw, signature = token.rsplit(".", 1)
    expected = hmac.new(_session_key(), raw.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        padded = raw + "=" * (-len(raw) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except Exception:
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload
