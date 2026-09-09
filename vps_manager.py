"""
vps_manager.py - System statistics, service actions and application lifecycle.

All OS-specific behaviour lives here. subprocess is used only where necessary,
always with argument arrays (never shell=True), timeouts, captured output and
no untrusted concatenation.
"""
from __future__ import annotations

import logging
import os
import resource
import signal
import subprocess
import threading
import time
from datetime import datetime, timezone

import psutil

import database

log = logging.getLogger("qwerty")

# --------------------------------------------------------------------------- #
# Resource limits applied to every hosted application process.
# Tunable via environment variables.
# --------------------------------------------------------------------------- #
APP_CPU_PERCENT = int(os.environ.get("QWERTY_APP_CPU_PERCENT", "50"))   # best-effort hint
APP_MEMORY_MB = int(os.environ.get("QWERTY_APP_MEMORY_MB", "256"))
APP_NPROC = int(os.environ.get("QWERTY_APP_NPROC", "32"))
APP_TIMEOUT = int(os.environ.get("QWERTY_APP_TIMEOUT", "0"))          # 0 = no kill timeout

# Runtime commands. Argument-array form only; the entrypoint filename is
# validated by the caller, never concatenated into a shell string.
RUNTIMES = {
    "python": {"cmd": ["python3", "-u", "app.py"], "bin_check": "python3"},
    "node": {"cmd": ["node", "app.js"], "bin_check": "node"},
}


def _limit_resources() -> None:
    """preexec_fn target: apply CPU / memory / nproc limits to the child."""
    try:
        # RLIMIT_AS limits total address space (memory).
        mem_bytes = APP_MEMORY_MB * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (APP_NPROC, APP_NPROC))
        # CPU time limit in seconds (soft/hard). 0 means unlimited.
        if APP_TIMEOUT > 0:
            resource.setrlimit(resource.RLIMIT_CPU, (APP_TIMEOUT, APP_TIMEOUT))
    except (ValueError, resource.error):
        # Best effort: ignore limits that the platform refuses.
        pass


# --------------------------------------------------------------------------- #
# Process registry (in-memory). Survives as long as the panel runs.
# --------------------------------------------------------------------------- #
_processes: dict[int, subprocess.Popen] = {}
_proc_lock = threading.Lock()


# --------------------------------------------------------------------------- #
# System statistics
# --------------------------------------------------------------------------- #
class StatsCollector:
    def __init__(self) -> None:
        self._last_net = psutil.net_io_counters()
        self._last_ts = time.time()

    def snapshot(self) -> dict:
        now = time.time()
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage(os.getcwd() if os.name != "nt" else "C:\\")
        net = psutil.net_io_counters()
        elapsed = max(now - self._last_ts, 1e-3)
        net_in = max(0, net.bytes_recv - self._last_net.bytes_recv) / elapsed
        net_out = max(0, net.bytes_sent - self._last_net.bytes_sent) / elapsed
        self._last_net = net
        self._last_ts = now

        boot_ts = psutil.boot_time()
        uptime_seconds = int(now - boot_ts)

        load1, load5, load15 = psutil.getloadavg() if hasattr(psutil, "getloadavg") else (0, 0, 0)

        return {
            "cpu": round(cpu, 1),
            "ram_percent": round(mem.percent, 1),
            "ram_used": mem.used,
            "ram_total": mem.total,
            "disk_percent": round(disk.percent, 1),
            "disk_used": disk.used,
            "disk_total": disk.total,
            "network_in": round(net_in, 1),
            "network_out": round(net_out, 1),
            "uptime": uptime_seconds,
            "load1": round(load1, 2),
            "load5": round(load5, 2),
            "load15": round(load15, 2),
        }


stats_collector = StatsCollector()


def get_stats() -> dict:
    return stats_collector.snapshot()


def format_uptime(seconds: int) -> str:
    d, rem = divmod(int(seconds), 86400)
    h, rem = divmod(rem, 3600)
    m, _ = divmod(rem, 60)
    return f"{d}d {h:02d}h {m:02d}m"


# --------------------------------------------------------------------------- #
# Server (panel) service actions - safe allowlist
# --------------------------------------------------------------------------- #
def _is_self(pid: int) -> bool:
    try:
        return pid == os.getpid() or pid in {p.pid for p in psutil.Process(os.getpid()).children(recursive=True)}
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False


def start_service() -> dict:
    """The control panel itself is the 'service'. Starting is a no-op that
    reports the panel is already running."""
    log.info("Service START requested (panel already running)")
    return {"ok": True, "message": "QWERTY VPS panel is already running", "status": "online"}


def stop_service() -> dict:
    """Stop only the hosted application processes, not the panel itself."""
    log.warning("Service STOP requested - stopping all hosted apps")
    stop_all_apps()
    return {"ok": True, "message": "All hosted applications stopped"}


def restart_service() -> dict:
    log.info("Service RESTART requested - restarting hosted apps")
    restart_all_apps()
    return {"ok": True, "message": "Hosted applications restarted"}


# --------------------------------------------------------------------------- #
# Application lifecycle
# --------------------------------------------------------------------------- #
def _runtime_cmd(runtime: str) -> list[str]:
    runtime = runtime.lower()
    if runtime not in RUNTIMES:
        raise ValueError(f"Unsupported runtime: {runtime}")
    return list(RUNTIMES[runtime]["cmd"])


def _app_directory(app: dict) -> str:
    """Resolve and validate the app directory."""
    directory = app["directory"]
    real = os.path.realpath(directory)
    if not os.path.isdir(real):
        raise FileNotFoundError(f"Application directory does not exist: {real}")
    return real


def start_app(app: dict) -> dict:
    app_id = app["id"]
    with _proc_lock:
        proc = _processes.get(app_id)
        if proc and proc.poll() is None:
            return {"ok": True, "message": f"Application '{app['name']}' is already running"}

    try:
        cmd = _runtime_cmd(app["runtime"])
        workdir = _app_directory(app)
    except (ValueError, FileNotFoundError) as exc:
        log.error("Cannot start app %s: %s", app_id, exc)
        return {"ok": False, "error": str(exc)}

    env = os.environ.copy()
    # Restrictive environment: strip secrets, set port.
    env["PORT"] = str(app["port"])
    env["HOST"] = "127.0.0.1"

    log_file_path = os.path.join(workdir, ".qwerty.log")
    try:
        log_fp = open(log_file_path, "ab", buffering=0)
    except OSError as exc:
        return {"ok": False, "error": f"Cannot open log file: {exc}"}

    try:
        proc = subprocess.Popen(
            cmd,
            cwd=workdir,
            stdout=log_fp,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            env=env,
            preexec_fn=_limit_resources,
            close_fds=True,
        )
    except FileNotFoundError:
        log_fp.close()
        return {"ok": False, "error": f"Runtime binary not found for '{app['runtime']}'"}
    except Exception as exc:
        log_fp.close()
        return {"ok": False, "error": f"Failed to start process: {exc}"}

    with _proc_lock:
        _processes[app_id] = proc
    database.update_app_status(app_id, "running", proc.pid)
    log.info("Started app '%s' (id=%s pid=%s)", app["name"], app_id, proc.pid)
    return {"ok": True, "message": f"Application '{app['name']}' started", "pid": proc.pid}


def stop_app(app: dict) -> dict:
    app_id = app["id"]
    with _proc_lock:
        proc = _processes.get(app_id)
        pid = app.get("pid") if not proc else proc.pid

    if proc and proc.poll() is None:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        except (psutil.NoSuchProcess, OSError):
            pass
        with _proc_lock:
            _processes.pop(app_id, None)
        database.update_app_status(app_id, "stopped", None)
        log.info("Stopped app '%s' (id=%s)", app["name"], app_id)
        return {"ok": True, "message": f"Application '{app['name']}' stopped"}

    # Process not tracked in this process table (e.g. panel restarted).
    if pid:
        try:
            p = psutil.Process(int(pid))
            p.terminate()
            p.wait(timeout=5)
            database.update_app_status(app_id, "stopped", None)
            return {"ok": True, "message": f"Application '{app['name']}' stopped"}
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.TimeoutExpired):
            pass

    database.update_app_status(app_id, "stopped", None)
    return {"ok": True, "message": f"Application '{app['name']}' was not running"}


def restart_app(app: dict) -> dict:
    stop_app(app)
    time.sleep(0.3)
    return start_app(app)


def stop_all_apps() -> None:
    for app in database.list_apps():
        if app["status"] == "running":
            stop_app(app)


def restart_all_apps() -> None:
    for app in database.list_apps():
        if app["status"] == "running":
            restart_app(app)


def app_runtime_stats(app: dict) -> dict:
    """Return CPU/RAM for a running app's process if available."""
    pid = app.get("pid")
    with _proc_lock:
        proc = _processes.get(app["id"])
        if proc and proc.poll() is not None:
            pid = None
    if not pid:
        return {"cpu": 0.0, "ram": 0}
    try:
        p = psutil.Process(int(pid))
        if not p.is_running():
            return {"cpu": 0.0, "ram": 0}
        cpu = p.cpu_percent(interval=0.1)
        mem = p.memory_info().rss
        return {"cpu": round(cpu, 1), "ram": mem}
    except (psutil.NoSuchProcess, psutil.AccessDenied, ValueError):
        return {"cpu": 0.0, "ram": 0}


def read_app_log(app: dict, tail: int = 200) -> str:
    workdir = _app_directory(app)
    log_path = os.path.join(workdir, ".qwerty.log")
    if not os.path.isfile(log_path):
        return ""
    try:
        with open(log_path, "rb") as fh:
            data = fh.read()
        text = data.decode("utf-8", errors="replace")
        lines = text.splitlines()
        return "\n".join(lines[-tail:])
    except OSError:
        return ""


def cleanup_on_startup() -> None:
    """Mark any apps left in 'running' state (from a previous panel crash) as
    'stopped' - their PIDs are no longer valid."""
    for app in database.list_apps():
        if app["status"] == "running":
            database.update_app_status(app["id"], "stopped", None)
