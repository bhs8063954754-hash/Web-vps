"""
app.py - QWERTY VPS control panel (FastAPI).

Run with:
    python app.py
or
    uvicorn app:app --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tarfile
import time
from collections import deque
from logging.handlers import RotatingFileHandler
from pathlib import Path

from fastapi import Depends, FastAPI, Request, UploadFile, File, Form, HTTPException, WebSocket, WebSocketDisconnect
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware

import database
import security
import vps_manager

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY = os.environ.get("QWERTY_SECRET_KEY", "CHANGE-ME-in-production-please-use-a-long-random-string")
ADMIN_USERNAME = os.environ.get("QWERTY_ADMIN_USER", "bhs")
ADMIN_PASSWORD = os.environ.get("QWERTY_ADMIN_PASS", "bhs")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# --------------------------------------------------------------------------- #
# Logging setup
# --------------------------------------------------------------------------- #
class WebSocketLogHandler(logging.Handler):
    """Buffers log records so the /ws/logs endpoint can stream them."""
    def __init__(self, capacity: int = 500) -> None:
        super().__init__()
        self.buffer: deque = deque(maxlen=capacity)
        self.subscribers: set[asyncio.Queue] = set()

    def emit(self, record: logging.LogRecord) -> None:
        entry = {
            "ts": time.strftime("%H:%M:%S", time.localtime(record.created)),
            "level": record.levelname,
            "message": self.format(record),
        }
        self.buffer.append(entry)
        # Push to any connected log websocket subscribers.
        for q in list(self.subscribers):
            try:
                q.put_nowait(entry)
            except asyncio.QueueFull:
                pass


ws_log_handler = WebSocketLogHandler()
ws_log_handler.setFormatter(logging.Formatter("%(message)s"))


def setup_logging() -> None:
    Path(LOG_DIR).mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        os.path.join(LOG_DIR, "qwerty.log"),
        maxBytes=2 * 1024 * 1024,
        backupCount=5,
    )
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")
    )
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    # Avoid duplicate handlers on reload.
    if not any(isinstance(h, RotatingFileHandler) for h in root.handlers):
        root.addHandler(file_handler)
    if not any(isinstance(h, WebSocketLogHandler) for h in root.handlers):
        root.addHandler(ws_log_handler)


log = logging.getLogger("qwerty")

# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #
app = FastAPI(title="QWERTY VPS", docs_url=None, redoc_url=None)

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    session_cookie="qwerty_session",
    same_site="lax",
    https_only=False,  # set True behind TLS in production
    max_age=60 * 60 * 12,
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; connect-src 'self' ws: wss:; font-src 'self'; "
            "frame-ancestors 'none';"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


# --------------------------------------------------------------------------- #
# Startup / shutdown
# --------------------------------------------------------------------------- #
@app.on_event("startup")
async def on_startup() -> None:
    setup_logging()
    database.init_db()
    security.ensure_hosting_dirs()
    # Seed admin if missing.
    if not database.get_user_by_username(ADMIN_USERNAME):
        database.create_user(ADMIN_USERNAME, security.hash_password(ADMIN_PASSWORD), is_admin=True)
        log.info("Seeded admin user '%s'", ADMIN_USERNAME)
    vps_manager.cleanup_on_startup()
    log.info("QWERTY VPS panel started")


@app.on_event("shutdown")
async def on_shutdown() -> None:
    vps_manager.stop_all_apps()
    log.info("QWERTY VPS panel stopped")


# --------------------------------------------------------------------------- #
# Helper
# --------------------------------------------------------------------------- #
def ok(message: str = "Operation completed", **extra) -> dict:
    return {"ok": True, "message": message, **extra}


def fail(error: str, **extra) -> dict:
    return {"ok": False, "error": error, **extra}


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "0.0.0.0"


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    if security.get_current_user(request):
        return RedirectResponse(url="/dashboard")
    return templates.TemplateResponse(request, "index.html")


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    if not security.get_current_user(request):
        return RedirectResponse(url="/")
    security.get_csrf_token(request)
    return templates.TemplateResponse(request, "index.html")


# --------------------------------------------------------------------------- #
# Auth API
# --------------------------------------------------------------------------- #
@app.post("/api/login")
async def api_login(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(fail("Invalid request body"), status_code=400)
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    ip = client_ip(request)

    if security.login_limiter.is_locked(ip):
        log.warning("Login blocked for %s (rate limit)", ip)
        return JSONResponse(
            fail("Too many failed attempts. Please wait and try again."),
            status_code=429,
        )

    if not username or not password:
        return JSONResponse(fail("Username and password required"), status_code=400)

    user = database.get_user_by_username(username)
    if not user or not security.verify_password(password, user["password_hash"]):
        security.login_limiter.record_failure(ip)
        database.log_activity(user["id"] if user else None, f"login:{username}", "failure")
        log.warning("Login failure for '%s' from %s", username, ip)
        return JSONResponse(fail("Invalid credentials"), status_code=401)

    security.login_limiter.record_success(ip)
    security.login_user(request, user["id"])
    database.log_activity(user["id"], "login", "success")
    log.info("Login success for '%s' from %s", username, ip)
    return ok("Login successful", is_admin=bool(user["is_admin"]),
              username=user["username"])


@app.post("/api/logout")
async def api_logout(request: Request):
    user = security.get_current_user(request)
    if user:
        database.log_activity(user["id"], "logout", "success")
    security.logout_user(request)
    return ok("Logged out")


@app.get("/api/me")
async def api_me(user: dict = Depends(security.require_user)):
    return {
        "ok": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "is_admin": bool(user["is_admin"]),
            "created_at": user["created_at"],
        },
    }


@app.get("/api/csrf")
async def api_csrf(request: Request):
    if not security.get_current_user(request):
        raise HTTPException(status_code=401, detail="Authentication required")
    return {"ok": True, "csrf": security.get_csrf_token(request)}


# --------------------------------------------------------------------------- #
# Dashboard / stats API
# --------------------------------------------------------------------------- #
@app.get("/api/stats")
async def api_stats(user: dict = Depends(security.require_user)):
    return {"ok": True, "stats": vps_manager.get_stats()}


@app.get("/api/server")
async def api_server(user: dict = Depends(security.require_user)):
    stats = vps_manager.get_stats()
    return {
        "ok": True,
        "server": {
            "status": "online",
            "hostname": os.uname().nodename if hasattr(os, "uname") else "server",
            "os": f"{os.uname().sysname} {os.uname().release}" if hasattr(os, "uname") else os.name,
            "uptime": vps_manager.format_uptime(stats["uptime"]),
            "load": f"{stats['load1']} {stats['load5']} {stats['load15']}",
        },
    }


@app.post("/api/server/{action}")
async def api_server_action(action: str, user: dict = Depends(security.require_admin)):
    if action not in {"start", "stop", "restart"}:
        return JSONResponse(fail("Unknown server action"), status_code=400)
    database.log_activity(user["id"], f"server:{action}", "success")
    result = getattr(vps_manager, f"{action}_service")()
    return result


# --------------------------------------------------------------------------- #
# Applications API
# --------------------------------------------------------------------------- #
ALLOWED_RUNTIMES = {"python", "node"}


@app.get("/api/apps")
async def api_list_apps(user: dict = Depends(security.require_user)):
    apps = database.list_apps(user["id"] if not user["is_admin"] else None)
    out = []
    for a in apps:
        rt = vps_manager.app_runtime_stats(a) if a["status"] == "running" else {"cpu": 0.0, "ram": 0}
        out.append({
            "id": a["id"],
            "name": a["name"],
            "runtime": a["runtime"],
            "directory": a["directory"],
            "port": a["port"],
            "status": a["status"],
            "created_at": a["created_at"],
            "cpu": rt["cpu"],
            "ram": rt["ram"],
        })
    return {"ok": True, "apps": out}


@app.post("/api/apps")
async def api_create_app(request: Request, user: dict = Depends(security.require_user)):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(fail("Invalid request body"), status_code=400)
    name = str(payload.get("name", "")).strip()
    runtime = str(payload.get("runtime", "")).strip().lower()
    port = payload.get("port")
    if not name or not re_safe_name(name):
        return JSONResponse(fail("Invalid application name"), status_code=400)
    if runtime not in ALLOWED_RUNTIMES:
        return JSONResponse(fail("Unsupported runtime"), status_code=400)
    try:
        port = int(port)
    except (TypeError, ValueError):
        return JSONResponse(fail("Invalid port"), status_code=400)
    if not (1 < port < 65535):
        return JSONResponse(fail("Port must be between 2 and 65535"), status_code=400)

    # Create a dedicated, isolated directory for the app under HOSTING_ROOT.
    safe_dir_name = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    app_dir = os.path.join(security.HOSTING_ROOT, f"app-{safe_dir_name}-{int(time.time())}")
    app_dir = os.path.realpath(app_dir)
    # Ensure it stays inside the hosting root.
    if os.path.commonpath([security.HOSTING_ROOT, app_dir]) != os.path.realpath(security.HOSTING_ROOT):
        return JSONResponse(fail("Invalid directory"), status_code=400)
    os.makedirs(app_dir, exist_ok=True)
    # Seed a minimal entrypoint so the app can actually start.
    if runtime == "python":
        with open(os.path.join(app_dir, "app.py"), "w") as f:
            f.write(APP_STUB_PYTHON.format(port=port))
    else:
        with open(os.path.join(app_dir, "app.js"), "w") as f:
            f.write(APP_STUB_NODE.format(port=port))

    app_id = database.create_app(user["id"], name, runtime, app_dir, port)
    database.log_activity(user["id"], f"app:create:{name}", "success")
    log.info("Created app '%s' (id=%s runtime=%s port=%s)", name, app_id, runtime, port)
    return ok("Application created", id=app_id)


@app.get("/api/apps/{app_id}")
async def api_get_app(app_id: int, user: dict = Depends(security.require_user)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not user["is_admin"] and app["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your application")
    rt = vps_manager.app_runtime_stats(app) if app["status"] == "running" else {"cpu": 0.0, "ram": 0}
    logs = vps_manager.read_app_log(app)
    return {
        "ok": True,
        "app": {
            "id": app["id"], "name": app["name"], "runtime": app["runtime"],
            "directory": app["directory"], "port": app["port"], "status": app["status"],
            "created_at": app["created_at"], "cpu": rt["cpu"], "ram": rt["ram"],
        },
        "logs": logs,
    }


@app.post("/api/apps/{app_id}/start")
async def api_app_start(app_id: int, user: dict = Depends(security.require_user)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not user["is_admin"] and app["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your application")
    if app["status"] == "disabled":
        return JSONResponse(fail("Application is disabled by admin"), status_code=403)
    result = vps_manager.start_app(app)
    database.log_activity(user["id"], f"app:start:{app['name']}", "success" if result["ok"] else "failure")
    return result


@app.post("/api/apps/{app_id}/stop")
async def api_app_stop(app_id: int, user: dict = Depends(security.require_user)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not user["is_admin"] and app["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your application")
    result = vps_manager.stop_app(app)
    database.log_activity(user["id"], f"app:stop:{app['name']}", "success")
    return result


@app.post("/api/apps/{app_id}/restart")
async def api_app_restart(app_id: int, user: dict = Depends(security.require_user)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not user["is_admin"] and app["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your application")
    if app["status"] == "disabled":
        return JSONResponse(fail("Application is disabled by admin"), status_code=403)
    result = vps_manager.restart_app(app)
    database.log_activity(user["id"], f"app:restart:{app['name']}", "success" if result["ok"] else "failure")
    return result


@app.delete("/api/apps/{app_id}")
async def api_app_delete(app_id: int, user: dict = Depends(security.require_user)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not user["is_admin"] and app["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your application")
    vps_manager.stop_app(app)
    database.delete_app(app_id)
    database.log_activity(user["id"], f"app:delete:{app['name']}", "success")
    log.info("Deleted app '%s' (id=%s)", app["name"], app_id)
    return ok("Application deleted")


# --------------------------------------------------------------------------- #
# Console: safe predefined actions
# --------------------------------------------------------------------------- #
@app.post("/api/apps/{app_id}/console/{action}")
async def api_app_console(app_id: int, action: str, user: dict = Depends(security.require_user)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    if not user["is_admin"] and app["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your application")

    if action == "logs":
        return {"ok": True, "logs": vps_manager.read_app_log(app)}
    if action == "clear_logs":
        try:
            path = os.path.join(os.path.realpath(app["directory"]), ".qwerty.log")
            if os.path.isfile(path):
                open(path, "w").close()
        except OSError as exc:
            return JSONResponse(fail(str(exc)), status_code=500)
        return ok("Logs cleared")
    if action == "install_deps":
        return _install_deps(app, user)
    if action in {"start", "stop", "restart"}:
        result = getattr(vps_manager, f"{action}_app")(app)
        database.log_activity(user["id"], f"console:{action}:{app['name']}", "success" if result.get("ok") else "failure")
        return result
    return JSONResponse(fail("Unknown console action"), status_code=400)


def _install_deps(app: dict, user: dict) -> dict:
    """Install dependencies from a requirements.txt / package.json using a strict
    allowlist of tooling. No arbitrary shell execution."""
    workdir = os.path.realpath(app["directory"])
    if os.path.commonpath([security.HOSTING_ROOT, workdir]) != os.path.realpath(security.HOSTING_ROOT):
        return fail("Invalid directory")
    import subprocess as sp
    try:
        if app["runtime"] == "python":
            req = os.path.join(workdir, "requirements.txt")
            if not os.path.isfile(req):
                return fail("No requirements.txt found in application directory")
            res = sp.run(["pip3", "install", "--no-input", "-r", req],
                         capture_output=True, text=True, timeout=120, cwd=workdir)
        else:
            pkg = os.path.join(workdir, "package.json")
            if not os.path.isfile(pkg):
                return fail("No package.json found in application directory")
            res = sp.run(["npm", "install", "--no-audit", "--no-fund"],
                         capture_output=True, text=True, timeout=180, cwd=workdir)
        if res.returncode != 0:
            log.warning("Dependency install failed for app %s: %s", app["id"], res.stderr[:500])
            return fail("Dependency install failed", stderr=res.stderr[-2000:])
        database.log_activity(user["id"], f"console:install_deps:{app['name']}", "success")
        return ok("Dependencies installed")
    except sp.TimeoutExpired:
        return fail("Dependency install timed out")
    except FileNotFoundError as exc:
        return fail(f"Tool not found: {exc.filename}")


# --------------------------------------------------------------------------- #
# File manager API
# --------------------------------------------------------------------------- #
@app.get("/api/files")
async def api_files_list(request: Request, user: dict = Depends(security.require_user)):
    rel = request.query_params.get("path", "")
    try:
        target = security.safe_join_path(rel)
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    if not os.path.isdir(target):
        return JSONResponse(fail("Not a directory"), status_code=400)
    items = []
    try:
        for name in os.listdir(target):
            full = os.path.join(target, name)
            stat = os.stat(full)
            items.append({
                "name": name,
                "type": "dir" if os.path.isdir(full) else "file",
                "size": stat.st_size if os.path.isfile(full) else 0,
                "modified": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime)),
            })
    except OSError as exc:
        return JSONResponse(fail(str(exc)), status_code=500)
    items.sort(key=lambda x: (x["type"] != "dir", x["name"].lower()))
    rel_display = os.path.relpath(target, security.HOSTING_ROOT)
    return {"ok": True, "path": rel_display, "items": items}


@app.post("/api/files/upload")
async def api_files_upload(request: Request, user: dict = Depends(security.require_user),
                           path: str = Form(...), file: UploadFile = File(...)):
    try:
        target_dir = security.safe_join_path(path)
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    if not os.path.isdir(target_dir):
        return JSONResponse(fail("Target directory does not exist"), status_code=400)
    try:
        filename = security.safe_filename(file.filename or "upload.bin")
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    dest = os.path.join(target_dir, filename)
    if os.path.realpath(dest) != dest and os.path.commonpath([security.HOSTING_ROOT, os.path.realpath(dest)]) != os.path.realpath(security.HOSTING_ROOT):
        return JSONResponse(fail("Invalid destination"), status_code=400)
    MAX_UPLOAD = 50 * 1024 * 1024
    written = 0
    try:
        with open(dest, "wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                written += len(chunk)
                if written > MAX_UPLOAD:
                    out.close()
                    os.remove(dest)
                    return JSONResponse(fail("File exceeds 50 MB limit"), status_code=413)
                out.write(chunk)
    except OSError as exc:
        return JSONResponse(fail(str(exc)), status_code=500)
    database.log_activity(user["id"], f"file:upload:{filename}", "success")
    log.info("File uploaded: %s (%d bytes)", filename, written)
    return ok("File uploaded", name=filename, size=written)


@app.post("/api/files/mkdir")
async def api_files_mkdir(request: Request, user: dict = Depends(security.require_user)):
    payload = await request.json()
    rel = str(payload.get("path", ""))
    name = str(payload.get("name", ""))
    try:
        parent = security.safe_join_path(rel)
        name = security.safe_filename(name)
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    new_dir = os.path.join(parent, name)
    try:
        os.makedirs(new_dir, exist_ok=False)
    except (OSError, FileExistsError) as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    database.log_activity(user["id"], f"file:mkdir:{name}", "success")
    return ok("Folder created")


@app.delete("/api/files")
async def api_files_delete(request: Request, user: dict = Depends(security.require_user)):
    payload = await request.json()
    rel = str(payload.get("path", ""))
    try:
        target = security.safe_join_path(rel)
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    if os.path.realpath(target) == os.path.realpath(security.HOSTING_ROOT):
        return JSONResponse(fail("Cannot delete the hosting root"), status_code=400)
    try:
        if os.path.isdir(target):
            import shutil
            shutil.rmtree(target)
        else:
            os.remove(target)
    except OSError as exc:
        return JSONResponse(fail(str(exc)), status_code=500)
    database.log_activity(user["id"], f"file:delete:{rel}", "success")
    return ok("Deleted")


@app.post("/api/files/rename")
async def api_files_rename(request: Request, user: dict = Depends(security.require_user)):
    payload = await request.json()
    rel = str(payload.get("path", ""))
    new_name = str(payload.get("name", ""))
    try:
        target = security.safe_join_path(rel)
        new_name = security.safe_filename(new_name)
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    dest = os.path.join(os.path.dirname(target), new_name)
    if os.path.commonpath([security.HOSTING_ROOT, os.path.realpath(dest)]) != os.path.realpath(security.HOSTING_ROOT):
        return JSONResponse(fail("Invalid destination"), status_code=400)
    try:
        os.rename(target, dest)
    except OSError as exc:
        return JSONResponse(fail(str(exc)), status_code=500)
    return ok("Renamed")


@app.get("/api/files/download")
async def api_files_download(request: Request, user: dict = Depends(security.require_user)):
    rel = request.query_params.get("path", "")
    try:
        target = security.safe_join_path(rel)
    except ValueError as exc:
        return JSONResponse(fail(str(exc)), status_code=400)
    if not os.path.isfile(target):
        return JSONResponse(fail("File not found"), status_code=404)
    return FileResponse(target, filename=os.path.basename(target))


# --------------------------------------------------------------------------- #
# Backups API
# --------------------------------------------------------------------------- #
@app.get("/api/backups")
async def api_list_backups(user: dict = Depends(security.require_user)):
    backups = database.list_backups(user["id"] if not user["is_admin"] else None)
    return {"ok": True, "backups": backups}


@app.post("/api/backups")
async def api_create_backup(request: Request, user: dict = Depends(security.require_user)):
    payload = await request.json()
    app_id = payload.get("application_id")
    app = None
    if app_id:
        app = database.get_app(int(app_id))
        if not app:
            return JSONResponse(fail("Application not found"), status_code=404)
        if not user["is_admin"] and app["user_id"] != user["id"]:
            return JSONResponse(fail("Not your application"), status_code=403)
        source_dir = os.path.realpath(app["directory"])
    else:
        source_dir = os.path.realpath(security.HOSTING_ROOT)

    # Validate the source stays inside the hosting root.
    if os.path.commonpath([security.HOSTING_ROOT, source_dir]) != os.path.realpath(security.HOSTING_ROOT):
        return JSONResponse(fail("Invalid backup source"), status_code=400)

    ts = time.strftime("%Y-%m-%d-%H%M%S")
    filename = f"backup-{ts}.tar.gz"
    backup_path = os.path.join(security.BACKUP_ROOT, filename)
    backup_path = os.path.realpath(backup_path)
    if os.path.commonpath([security.BACKUP_ROOT, backup_path]) != os.path.realpath(security.BACKUP_ROOT):
        return JSONResponse(fail("Invalid backup path"), status_code=400)

    try:
        with tarfile.open(backup_path, "w:gz") as tar:
            tar.add(source_dir, arcname=os.path.basename(source_dir), recursive=True)
        size = os.path.getsize(backup_path)
    except OSError as exc:
        return JSONResponse(fail(f"Backup failed: {exc}"), status_code=500)

    bid = database.create_backup(user["id"], int(app_id) if app_id else None, filename, size)
    database.log_activity(user["id"], f"backup:create:{filename}", "success")
    log.info("Backup created: %s (%d bytes)", filename, size)
    return ok("Backup created", id=bid, filename=filename, size=size)


@app.delete("/api/backups/{backup_id}")
async def api_delete_backup(backup_id: int, user: dict = Depends(security.require_user)):
    b = database.get_backup(backup_id)
    if not b:
        raise HTTPException(status_code=404, detail="Backup not found")
    if not user["is_admin"] and b["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your backup")
    path = os.path.join(security.BACKUP_ROOT, b["filename"])
    path = os.path.realpath(path)
    if os.path.commonpath([security.BACKUP_ROOT, path]) == os.path.realpath(security.BACKUP_ROOT) and os.path.isfile(path):
        try:
            os.remove(path)
        except OSError as exc:
            return JSONResponse(fail(str(exc)), status_code=500)
    database.delete_backup(backup_id)
    database.log_activity(user["id"], f"backup:delete:{b['filename']}", "success")
    return ok("Backup deleted")


@app.get("/api/backups/{backup_id}/download")
async def api_download_backup(backup_id: int, user: dict = Depends(security.require_user)):
    b = database.get_backup(backup_id)
    if not b:
        raise HTTPException(status_code=404, detail="Backup not found")
    if not user["is_admin"] and b["user_id"] != user["id"]:
        raise HTTPException(status_code=403, detail="Not your backup")
    path = os.path.realpath(os.path.join(security.BACKUP_ROOT, b["filename"]))
    if os.path.commonpath([security.BACKUP_ROOT, path]) != os.path.realpath(security.BACKUP_ROOT):
        raise HTTPException(status_code=400, detail="Invalid path")
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Backup file missing")
    return FileResponse(path, filename=b["filename"], media_type="application/gzip")


# --------------------------------------------------------------------------- #
# Admin API
# --------------------------------------------------------------------------- #
@app.get("/api/admin/overview")
async def api_admin_overview(admin: dict = Depends(security.require_admin)):
    stats = vps_manager.get_stats()
    return {
        "ok": True,
        "overview": {
            "total_users": database.user_count(),
            "total_apps": database.app_count(),
            "online_apps": database.online_app_count(),
            "total_backups": database.backup_count(),
            "cpu": stats["cpu"],
            "ram": stats["ram_percent"],
            "disk": stats["disk_percent"],
        },
    }


@app.get("/api/admin/users")
async def api_admin_users(admin: dict = Depends(security.require_admin)):
    return {"ok": True, "users": database.list_users()}


@app.get("/api/admin/apps")
async def api_admin_apps(admin: dict = Depends(security.require_admin)):
    return {"ok": True, "apps": database.list_apps()}


@app.get("/api/admin/logs")
async def api_admin_logs(admin: dict = Depends(security.require_admin)):
    return {"ok": True, "logs": database.list_activity()}


@app.post("/api/admin/apps/{app_id}/disable")
async def api_admin_disable(app_id: int, admin: dict = Depends(security.require_admin)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    vps_manager.stop_app(app)
    database.update_app_status(app_id, "disabled", None)
    database.log_activity(admin["id"], f"admin:disable:{app['name']}", "success")
    return ok("Application disabled")


@app.post("/api/admin/apps/{app_id}/enable")
async def api_admin_enable(app_id: int, admin: dict = Depends(security.require_admin)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    database.update_app_status(app_id, "stopped", None)
    database.log_activity(admin["id"], f"admin:enable:{app['name']}", "success")
    return ok("Application enabled")


@app.delete("/api/admin/apps/{app_id}")
async def api_admin_delete_app(app_id: int, admin: dict = Depends(security.require_admin)):
    app = database.get_app(app_id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    vps_manager.stop_app(app)
    database.delete_app(app_id)
    database.log_activity(admin["id"], f"admin:delete:{app['name']}", "success")
    return ok("Application deleted")


# --------------------------------------------------------------------------- #
# WebSockets
# --------------------------------------------------------------------------- #
@app.websocket("/ws/stats")
async def ws_stats(ws: WebSocket):
    token = ws.query_params.get("token")
    # Lightweight auth: the session cookie travels with the WS handshake
    # automatically, so we can read it from the ASGI scope.
    if not _ws_authenticated(ws):
        await ws.close(code=4401)
        return
    await ws.accept()
    try:
        while True:
            stats = vps_manager.get_stats()
            await ws.send_json(stats)
            await asyncio.sleep(1.5)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass


@app.websocket("/ws/logs")
async def ws_logs(ws: WebSocket):
    if not _ws_authenticated(ws):
        await ws.close(code=4401)
        return
    await ws.accept()
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    ws_log_handler.subscribers.add(q)
    # Replay the recent buffer first.
    for entry in list(ws_log_handler.buffer):
        try:
            await ws.send_json(entry)
        except Exception:
            break
    try:
        while True:
            entry = await q.get()
            await ws.send_json(entry)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        ws_log_handler.subscribers.discard(q)


def _ws_authenticated(ws: WebSocket) -> bool:
    """Check the signed session cookie from the ASGI scope headers."""
    headers = dict(ws.scope.get("headers", []))
    cookie_header = headers.get(b"cookie", b"").decode("latin-1")
    if not cookie_header:
        return False
    # We trust SessionMiddleware to have populated scope["session"] during the
    # handshake. If it did not, fall back to manual check is not feasible, so we
    # rely on scope["session"].
    session = ws.scope.get("session", {})
    return bool(session.get(security.SESSION_USER_KEY))


# --------------------------------------------------------------------------- #
# Small helpers + constants
# --------------------------------------------------------------------------- #
import re

def re_safe_name(name: str) -> str:
    return bool(re.match(r"^[A-Za-z0-9 _\-.]{1,64}$", name))


APP_STUB_PYTHON = '''"""Minimal QWERTY VPS hosted app stub."""
import os
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(os.environ.get("PORT", {port}))

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"Hello from QWERTY VPS hosted Python app!"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, fmt, *args):
        pass

if __name__ == "__main__":
    print(f"App listening on 127.0.0.1:{{PORT}}")
    HTTPServer(("127.0.0.1", PORT), H).serve_forever()
'''

APP_STUB_NODE = '''// Minimal QWERTY VPS hosted app stub.
const http = require("http");
const PORT = process.env.PORT || {port};
const server = http.createServer((req, res) => {{
  res.writeHead(200, {{ "Content-Type": "text/plain" }});
  res.end("Hello from QWERTY VPS hosted Node.js app!");
}});
server.listen(PORT, "127.0.0.1", () => {{
  console.log(`App listening on 127.0.0.1:${{PORT}}`);
}});
'''


# --------------------------------------------------------------------------- #
# Error handlers
# --------------------------------------------------------------------------- #
@app.exception_handler(HTTPException)
async def http_exc_handler(request: Request, exc: HTTPException):
    return JSONResponse({"ok": False, "error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    log.error("Unhandled error: %s", exc, exc_info=True)
    return JSONResponse({"ok": False, "error": "Internal server error"}, status_code=500)


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
