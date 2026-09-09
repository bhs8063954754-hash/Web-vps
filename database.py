"""
database.py - SQLite persistence layer for QWERTY VPS.

Handles:
  * database initialization + table creation
  * user creation + authentication lookup
  * application CRUD
  * backup CRUD
  * activity logging

All queries use parameterized SQL. No string concatenation.
"""
from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone

DB_PATH = os.environ.get("QWERTY_DB_PATH", os.path.join(os.path.dirname(__file__), "qwerty.db"))

# SQLite connections are not thread-safe by default. FastAPI may call us from a
# thread pool, so we guard every access with a single re-entrant lock.
_db_lock = threading.RLock()


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def get_conn():
    """Yield a connection bound to a row factory. Thread-safe."""
    conn = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create all tables if they do not exist."""
    with _db_lock, get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT    UNIQUE NOT NULL,
                password_hash TEXT    NOT NULL,
                created_at    TEXT    NOT NULL,
                is_admin      INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS servers (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT NOT NULL,
                status     TEXT NOT NULL DEFAULT 'online',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS applications (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER NOT NULL,
                name       TEXT    NOT NULL,
                runtime    TEXT    NOT NULL,
                directory  TEXT    NOT NULL,
                port       INTEGER NOT NULL,
                status     TEXT    NOT NULL DEFAULT 'stopped',
                pid        INTEGER,
                created_at TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS backups (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id        INTEGER NOT NULL,
                application_id INTEGER,
                filename       TEXT    NOT NULL,
                size           INTEGER NOT NULL DEFAULT 0,
                created_at     TEXT    NOT NULL,
                FOREIGN KEY (user_id)        REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (application_id) REFERENCES applications(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS activity_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                action     TEXT    NOT NULL,
                status     TEXT    NOT NULL DEFAULT 'success',
                created_at TEXT    NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
            );
            """
        )


# --------------------------------------------------------------------------- #
# Users
# --------------------------------------------------------------------------- #
def create_user(username: str, password_hash: str, is_admin: bool = False) -> int:
    with _db_lock, get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, created_at, is_admin) "
            "VALUES (?, ?, ?, ?)",
            (username, password_hash, _utcnow(), 1 if is_admin else 0),
        )
        return cur.lastrowid


def get_user_by_username(username: str) -> dict | None:
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
    return dict(row) if row else None


def get_user_by_id(user_id: int) -> dict | None:
    with _db_lock, get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with _db_lock, get_conn() as conn:
        rows = conn.execute(
            "SELECT id, username, created_at, is_admin FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def user_count() -> int:
    with _db_lock, get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]


# --------------------------------------------------------------------------- #
# Applications
# --------------------------------------------------------------------------- #
def create_app(user_id: int, name: str, runtime: str, directory: str, port: int) -> int:
    with _db_lock, get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO applications (user_id, name, runtime, directory, port, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, 'stopped', ?)",
            (user_id, name, runtime, directory, port, _utcnow()),
        )
        return cur.lastrowid


def get_app(app_id: int) -> dict | None:
    with _db_lock, get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM applications WHERE id = ?", (app_id,)
        ).fetchone()
    return dict(row) if row else None


def list_apps(user_id: int | None = None) -> list[dict]:
    with _db_lock, get_conn() as conn:
        if user_id is None:
            rows = conn.execute("SELECT * FROM applications ORDER BY id").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM applications WHERE user_id = ? ORDER BY id", (user_id,)
            ).fetchall()
    return [dict(r) for r in rows]


def update_app_status(app_id: int, status: str, pid: int | None = None) -> None:
    with _db_lock, get_conn() as conn:
        conn.execute(
            "UPDATE applications SET status = ?, pid = ? WHERE id = ?",
            (status, pid, app_id),
        )


def delete_app(app_id: int) -> None:
    with _db_lock, get_conn() as conn:
        conn.execute("DELETE FROM applications WHERE id = ?", (app_id,))


def app_count() -> int:
    with _db_lock, get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM applications").fetchone()[0]


def online_app_count() -> int:
    with _db_lock, get_conn() as conn:
        return conn.execute(
            "SELECT COUNT(*) FROM applications WHERE status = 'running'"
        ).fetchone()[0]


# --------------------------------------------------------------------------- #
# Backups
# --------------------------------------------------------------------------- #
def create_backup(user_id: int, application_id: int | None, filename: str, size: int) -> int:
    with _db_lock, get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO backups (user_id, application_id, filename, size, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, application_id, filename, size, _utcnow()),
        )
        return cur.lastrowid


def get_backup(backup_id: int) -> dict | None:
    with _db_lock, get_conn() as conn:
        row = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
    return dict(row) if row else None


def list_backups(user_id: int | None = None) -> list[dict]:
    with _db_lock, get_conn() as conn:
        if user_id is None:
            rows = conn.execute("SELECT * FROM backups ORDER BY id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM backups WHERE user_id = ? ORDER BY id DESC", (user_id,)
            ).fetchall()
    return [dict(r) for r in rows]


def delete_backup(backup_id: int) -> None:
    with _db_lock, get_conn() as conn:
        conn.execute("DELETE FROM backups WHERE id = ?", (backup_id,))


def backup_count() -> int:
    with _db_lock, get_conn() as conn:
        return conn.execute("SELECT COUNT(*) FROM backups").fetchone()[0]


# --------------------------------------------------------------------------- #
# Activity logs
# --------------------------------------------------------------------------- #
def log_activity(user_id: int | None, action: str, status: str = "success") -> None:
    with _db_lock, get_conn() as conn:
        conn.execute(
            "INSERT INTO activity_logs (user_id, action, status, created_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, action, status, _utcnow()),
        )


def list_activity(limit: int = 200) -> list[dict]:
    with _db_lock, get_conn() as conn:
        rows = conn.execute(
            "SELECT a.id, a.user_id, u.username, a.action, a.status, a.created_at "
            "FROM activity_logs a LEFT JOIN users u ON a.user_id = u.id "
            "ORDER BY a.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]
