"""
security.py - Authentication, authorization and input-safety helpers.

Provides:
  * Password hashing / verification (bcrypt via passlib)
  * Session helpers (used together with Starlette SessionMiddleware)
  * FastAPI dependencies: require_user, require_admin
  * Login rate limiting + brute-force protection
  * Safe path joining under a hosting root (path-traversal defence)
  * Filename validation
  * CSRF token generation / verification
"""
from __future__ import annotations

import os
import re
import secrets
import time
from collections import defaultdict
from pathlib import Path

from fastapi import Depends, HTTPException, Request, status
import bcrypt

import database

# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def hash_password(password: str) -> str:
    """Hash a password using bcrypt. bcrypt limits inputs to 72 bytes, so we
    pre-hash long passwords with sha256 to remain compatible."""
    raw = password.encode("utf-8")
    if len(raw) > 72:
        import hashlib
        raw = hashlib.sha256(raw).hexdigest().encode("utf-8")
    return bcrypt.hashpw(raw, bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        raw = password.encode("utf-8")
        if len(raw) > 72:
            import hashlib
            raw = hashlib.sha256(raw).hexdigest().encode("utf-8")
        return bcrypt.checkpw(raw, password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# Session helpers
# --------------------------------------------------------------------------- #
SESSION_USER_KEY = "user_id"


def login_user(request: Request, user_id: int) -> None:
    """Store the user id in the signed session cookie."""
    request.session[SESSION_USER_KEY] = user_id
    # Regenerate the CSRF token for the new session.
    request.session["csrf"] = generate_csrf_token()


def logout_user(request: Request) -> None:
    request.session.clear()


def get_current_user(request: Request) -> dict | None:
    user_id = request.session.get(SESSION_USER_KEY)
    if not user_id:
        return None
    return database.get_user_by_id(int(user_id))


# --------------------------------------------------------------------------- #
# FastAPI dependencies
# --------------------------------------------------------------------------- #
def require_user(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


def require_admin(user: dict = Depends(require_user)) -> dict:
    if not user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required",
        )
    return user


# --------------------------------------------------------------------------- #
# Rate limiting for the login endpoint
# --------------------------------------------------------------------------- #
class LoginRateLimiter:
    """Simple in-memory sliding-window limiter keyed by client IP."""

    def __init__(self, max_attempts: int = 5, window_seconds: int = 300,
                 lockout_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._attempts: dict[str, list[float]] = defaultdict(list)
        self._locked_until: dict[str, float] = {}

    def is_locked(self, ip: str) -> bool:
        until = self._locked_until.get(ip, 0)
        return time.time() < until

    def record_failure(self, ip: str) -> None:
        now = time.time()
        attempts = [t for t in self._attempts[ip] if now - t < self.window_seconds]
        attempts.append(now)
        self._attempts[ip] = attempts
        if len(attempts) >= self.max_attempts:
            self._locked_until[ip] = now + self.lockout_seconds

    def record_success(self, ip: str) -> None:
        self._attempts.pop(ip, None)
        self._locked_until.pop(ip, None)

    def remaining(self, ip: str) -> int:
        now = time.time()
        attempts = [t for t in self._attempts[ip] if now - t < self.window_seconds]
        return max(0, self.max_attempts - len(attempts))


login_limiter = LoginRateLimiter()


# --------------------------------------------------------------------------- #
# Path safety
# --------------------------------------------------------------------------- #
HOSTING_ROOT = os.environ.get(
    "QWERTY_HOSTING_ROOT", "/var/lib/qwerty-vps"
)
BACKUP_ROOT = os.environ.get(
    "QWERTY_BACKUP_ROOT", "/var/lib/qwerty-vps/backups"
)

# Directories the file manager must never expose.
_FORBIDDEN_PREFIXES = ("/etc", "/root", "/proc", "/sys", "/dev", "/boot", "/var/lib/qwerty-vps/.secrets")


def safe_join_path(user_path: str, root: str = HOSTING_ROOT) -> str:
    """
    Resolve ``user_path`` against ``root`` and ensure the final real path stays
    inside ``root``. Raises ValueError on traversal attempts.
    """
    root_real = os.path.realpath(root)
    candidate = os.path.realpath(os.path.join(root_real, user_path.lstrip("/")))
    if os.path.commonpath([root_real, candidate]) != root_real:
        raise ValueError("Path traversal detected")
    for forbidden in _FORBIDDEN_PREFIXES:
        if candidate == forbidden or candidate.startswith(forbidden + os.sep):
            raise ValueError("Access to this path is forbidden")
    return candidate


def safe_filename(name: str) -> str:
    """Validate a single filename component. Returns the cleaned name."""
    name = os.path.basename(name.strip())
    if not name:
        raise ValueError("Empty filename")
    if name in {".", ".."}:
        raise ValueError("Invalid filename")
    if not re.match(r"^[\w.\- ]+$", name):
        raise ValueError("Filename contains invalid characters")
    return name


# --------------------------------------------------------------------------- #
# CSRF
# --------------------------------------------------------------------------- #
def generate_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = generate_csrf_token()
        request.session["csrf"] = token
    return token


def verify_csrf(request: Request) -> None:
    """Verify the X-CSRF-Token header against the session token.

    Disabled for state-changing requests that arrive without a session cookie
    (those will simply fail the auth dependency first). CSRF matters because the
    cookie is sent automatically by the browser on cross-site requests.
    """
    header_token = request.headers.get("X-CSRF-Token", "")
    session_token = request.session.get("csrf", "")
    if not session_token or not secrets.compare_digest(header_token, session_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid CSRF token"
        )


def ensure_hosting_dirs() -> None:
    """Create the hosting + backup root directories if missing."""
    for d in (HOSTING_ROOT, BACKUP_ROOT):
        Path(d).mkdir(parents=True, exist_ok=True)
