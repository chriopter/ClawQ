import hashlib
import json
import os
import subprocess
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psutil
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from itsdangerous import BadSignature, URLSafeSerializer
from markdown_it import MarkdownIt


APP_START_UTC = datetime.now(timezone.utc)
AUTH_COOKIE = "clawq_auth"
README_PATH = Path("/root/workspaces/README.md")
OPENCLAW_CONFIG_PATH = Path(os.path.expanduser("~/.openclaw/openclaw.json"))
OPENCLAW_CRON_PATH = Path(os.path.expanduser("~/.openclaw/cron/jobs.json"))
OPENCLAW_AGENTS_DIR = Path(os.path.expanduser("~/.openclaw/agents"))
CLAUDE_CREDENTIALS_PATH = Path(os.path.expanduser("~/.claude/.credentials.json"))
CLAUDE_STATS_PATH = Path(os.path.expanduser("~/.claude/stats-cache.json"))
WORKSPACES_ROOT = Path("/root/workspaces")


def _password() -> str:
    password = os.getenv("CLAWQ_PASSWORD", "").strip()
    if not password:
        raise RuntimeError("CLAWQ_PASSWORD must be set")
    return password


def _cookie_secret() -> str:
    password = _password()
    return os.getenv("CLAWQ_COOKIE_SECRET", hashlib.sha256(password.encode()).hexdigest())


def _password_hash() -> str:
    return hashlib.sha256(_password().encode()).hexdigest()


def _cookie_secure() -> bool:
    return os.getenv("CLAWQ_COOKIE_SECURE", "false").strip().lower() in {"1", "true", "yes", "on"}


serializer = URLSafeSerializer(_cookie_secret(), salt="clawq-auth")
md = MarkdownIt("commonmark", {"html": False, "linkify": True, "typographer": True}).enable("table")

app = FastAPI(title="ClawQ WebGUI")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")


def is_authenticated(request: Request) -> bool:
    token = request.cookies.get(AUTH_COOKIE)
    if not token:
        return False

    try:
        payload = serializer.loads(token)
    except BadSignature:
        return False

    return payload.get("password_hash") == _password_hash()


def require_auth(request: Request):
    if not is_authenticated(request):
        return RedirectResponse(url="/login", status_code=303)
    return None


def _ensure_api_auth(request: Request):
    if is_authenticated(request):
        return None
    return JSONResponse(status_code=401, content={"error": "Unauthorized"})


def _clawq_health() -> dict:
    candidates = []
    for process in psutil.process_iter(["pid", "name", "cmdline", "create_time", "status"]):
        try:
            name = (process.info.get("name") or "").lower()
            cmdline = " ".join(process.info.get("cmdline") or []).lower()
            if "clawq" in name or "clawq" in cmdline:
                candidates.append(process.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    if not candidates:
        return {
            "running": False,
            "message": "No process with 'clawq' found.",
            "processes": [],
        }

    process_rows = []
    for proc in candidates:
        started = datetime.fromtimestamp(proc["create_time"], tz=timezone.utc)
        uptime_seconds = int((datetime.now(timezone.utc) - started).total_seconds())
        process_rows.append(
            {
                "pid": proc["pid"],
                "name": proc.get("name"),
                "status": proc.get("status"),
                "uptime_seconds": uptime_seconds,
            }
        )

    return {
        "running": True,
        "message": f"Found {len(process_rows)} ClawQ-like process(es).",
        "processes": process_rows,
    }


def _system_status() -> dict:
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    uptime_seconds = int((datetime.now(timezone.utc) - APP_START_UTC).total_seconds())

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "app_uptime_seconds": uptime_seconds,
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "memory": {
            "percent": vm.percent,
            "used": vm.used,
            "total": vm.total,
        },
        "disk_root": {
            "percent": disk.percent,
            "used": disk.used,
            "total": disk.total,
        },
        "clawq": _clawq_health(),
    }


def _json_or_none(path: Path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _mask_sensitive(obj):
    sensitive = {
        "token",
        "apikey",
        "api_key",
        "password",
        "secret",
        "tokens",
        "apikeys",
        "passwords",
        "secrets",
    }
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in sensitive else _mask_sensitive(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_mask_sensitive(item) for item in obj]
    return obj


def _openclaw_starters_data() -> dict:
    sessions = []
    if OPENCLAW_AGENTS_DIR.is_dir():
        for sessions_file in OPENCLAW_AGENTS_DIR.glob("*/sessions/sessions.json"):
            agent = sessions_file.parts[-3]
            data = _json_or_none(sessions_file)
            if not isinstance(data, dict):
                continue
            for key, session in data.items():
                if not isinstance(session, dict):
                    continue
                sessions.append(
                    {
                        "key": key,
                        "agent": agent,
                        "chat_type": session.get("chatType", ""),
                        "subject": session.get("subject", ""),
                        "updated_at": session.get("updatedAt", 0),
                    }
                )

    sessions.sort(key=lambda item: item.get("updated_at", 0), reverse=True)
    starters = [
        {"name": "Status", "prompt": "/status"},
        {"name": "Summarize Workspace", "prompt": "Summarize this workspace and next steps."},
        {"name": "Run Diagnostics", "prompt": "Run quick diagnostics and report issues."},
        {"name": "Draft Plan", "prompt": "Create a short execution plan for the current task."},
    ]
    return {"sessions": sessions[:20], "starters": starters}


def _usage_stats_data() -> dict:
    result = {
        "profiles": {},
        "credentials": {},
        "stats": {},
    }

    config = _json_or_none(OPENCLAW_CONFIG_PATH)
    if isinstance(config, dict):
        profiles = config.get("auth", {}).get("profiles", {})
        if isinstance(profiles, dict):
            for key, value in profiles.items():
                if isinstance(value, dict):
                    result["profiles"][key] = {
                        "provider": value.get("provider", key.split(":")[0]),
                        "mode": value.get("mode", ""),
                        "active": value.get("active", True),
                    }

    creds = _json_or_none(CLAUDE_CREDENTIALS_PATH)
    if isinstance(creds, dict):
        now_ms = int(time.time() * 1000)
        for key, value in creds.items():
            if isinstance(value, dict):
                expires = value.get("expiresAt", 0)
                result["credentials"][key] = {
                    "subscription_type": value.get("subscriptionType", ""),
                    "rate_limit_tier": value.get("rateLimitTier", ""),
                    "expired": expires > 0 and expires < now_ms,
                    "expires_at": expires,
                }

    stats = _json_or_none(CLAUDE_STATS_PATH)
    if isinstance(stats, dict):
        result["stats"] = {
            "last_computed_date": stats.get("lastComputedDate", ""),
            "total_sessions": stats.get("totalSessions", 0),
            "total_messages": stats.get("totalMessages", 0),
            "daily_activity": stats.get("dailyActivity", [])[-7:],
            "daily_model_tokens": stats.get("dailyModelTokens", [])[-7:],
            "first_session_date": stats.get("firstSessionDate", ""),
        }

    return result


def _settings_data() -> dict:
    return {
        "cookie_secure": _cookie_secure(),
        "readme_path": str(README_PATH),
        "readme_exists": README_PATH.exists(),
        "password_env_set": bool(os.getenv("CLAWQ_PASSWORD", "").strip()),
        "cookie_secret_env_set": bool(os.getenv("CLAWQ_COOKIE_SECRET", "").strip()),
    }


def _stt_status_data() -> dict:
    config = _json_or_none(OPENCLAW_CONFIG_PATH)
    if not isinstance(config, dict):
        return {"active": False, "openclaw_enabled": False, "models": [], "remote": None}

    audio = config.get("tools", {}).get("media", {}).get("audio", {})
    models = []
    auth_header = None
    for model in audio.get("models", []):
        if not isinstance(model, dict):
            continue
        cmd = model.get("command", "")
        args = model.get("args", [])
        provider = model.get("provider")
        if provider:
            models.append({"type": "provider", "provider": provider, "model": model.get("model", "")})
        else:
            entry = {"type": model.get("type", "cli"), "command": cmd}
            for arg in args:
                if isinstance(arg, str) and arg.startswith("http"):
                    entry["endpoint"] = arg
                if isinstance(arg, str) and arg.startswith("Authorization:"):
                    auth_header = arg.split(":", 1)[1].strip()
            models.append(entry)

    remote_status = None
    remote_model = next((m for m in models if m.get("endpoint")), None)
    if remote_model:
        try:
            endpoint = remote_model["endpoint"]
            base = endpoint.rsplit("/v1/", 1)[0] if "/v1/" in endpoint else endpoint.rstrip("/")
            req = urllib.request.Request(f"{base}/api/status")
            if auth_header:
                req.add_header("Authorization", auth_header if auth_header.startswith("Bearer") else f"Bearer {auth_header}")
            with urllib.request.urlopen(req, timeout=3) as response:
                remote_status = json.loads(response.read())
        except Exception:
            remote_status = None

    return {
        "active": audio.get("enabled", False) and bool(models),
        "openclaw_enabled": audio.get("enabled", False),
        "models": models,
        "remote": remote_status,
    }


def _cron_jobs_data() -> dict:
    data = _json_or_none(OPENCLAW_CRON_PATH)
    if not isinstance(data, dict):
        return {"jobs": []}
    jobs = data.get("jobs", [])
    if not isinstance(jobs, list):
        jobs = []
    return {"jobs": jobs}


def _run_git(cwd: Path, *args: str) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=6,
        )
    except Exception:
        return False, ""

    if completed.returncode != 0:
        return False, completed.stderr.strip() or completed.stdout.strip()
    return True, completed.stdout.strip()


def _workspaces_sync_data() -> dict:
    if not WORKSPACES_ROOT.exists():
        return {
            "path": str(WORKSPACES_ROOT),
            "exists": False,
            "is_git_repo": False,
            "in_sync": False,
            "status": "missing",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    ok_repo, _ = _run_git(WORKSPACES_ROOT, "rev-parse", "--is-inside-work-tree")
    if not ok_repo:
        return {
            "path": str(WORKSPACES_ROOT),
            "exists": True,
            "is_git_repo": False,
            "in_sync": False,
            "status": "not_git_repo",
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    ok_branch, branch = _run_git(WORKSPACES_ROOT, "rev-parse", "--abbrev-ref", "HEAD")
    ok_upstream, upstream = _run_git(WORKSPACES_ROOT, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    ok_status, porcelain = _run_git(WORKSPACES_ROOT, "status", "--porcelain")

    dirty_files = []
    if ok_status and porcelain:
        for line in porcelain.splitlines():
            if len(line) >= 4:
                dirty_files.append(line[3:].strip())

    ahead = 0
    behind = 0
    if ok_upstream:
        ok_counts, counts = _run_git(WORKSPACES_ROOT, "rev-list", "--left-right", "--count", "@{upstream}...HEAD")
        if ok_counts and counts:
            parts = counts.split()
            if len(parts) == 2:
                behind = int(parts[0])
                ahead = int(parts[1])

    dirty_count = len(dirty_files)
    if dirty_count == 0 and ahead == 0 and behind == 0 and ok_upstream:
        status = "synced"
    elif dirty_count > 0:
        status = "dirty"
    elif ahead > 0 and behind > 0:
        status = "diverged"
    elif ahead > 0:
        status = "ahead"
    elif behind > 0:
        status = "behind"
    else:
        status = "no_upstream"

    return {
        "path": str(WORKSPACES_ROOT),
        "exists": True,
        "is_git_repo": True,
        "branch": branch if ok_branch else "unknown",
        "upstream": upstream if ok_upstream else None,
        "ahead": ahead,
        "behind": behind,
        "dirty_count": dirty_count,
        "dirty_files": dirty_files[:15],
        "in_sync": status == "synced",
        "status": status,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _repo_git_status(repo_path: Path) -> dict:
    ok_branch, branch = _run_git(repo_path, "rev-parse", "--abbrev-ref", "HEAD")
    ok_upstream, upstream = _run_git(repo_path, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    ok_status, porcelain = _run_git(repo_path, "status", "--porcelain")

    dirty_files = []
    if ok_status and porcelain:
        for line in porcelain.splitlines():
            if len(line) >= 4:
                dirty_files.append(line[3:].strip())

    ahead = 0
    behind = 0
    if ok_upstream:
        ok_counts, counts = _run_git(repo_path, "rev-list", "--left-right", "--count", "@{upstream}...HEAD")
        if ok_counts and counts:
            parts = counts.split()
            if len(parts) == 2:
                behind = int(parts[0])
                ahead = int(parts[1])

    dirty_count = len(dirty_files)
    if dirty_count == 0 and ahead == 0 and behind == 0 and ok_upstream:
        status = "synced"
    elif dirty_count > 0:
        status = "dirty"
    elif ahead > 0 and behind > 0:
        status = "diverged"
    elif ahead > 0:
        status = "ahead"
    elif behind > 0:
        status = "behind"
    else:
        status = "no_upstream"

    last_push_at = None
    last_push_age_hours = None
    if ok_upstream:
        ok_push_ts, push_ts = _run_git(repo_path, "log", "-1", "--format=%ct", "@{upstream}")
        if ok_push_ts and push_ts.isdigit():
            pushed = datetime.fromtimestamp(int(push_ts), tz=timezone.utc)
            last_push_at = pushed.isoformat()
            last_push_age_hours = round((datetime.now(timezone.utc) - pushed).total_seconds() / 3600, 1)

    stale_uncommitted = bool(dirty_count > 0 and last_push_age_hours is not None and last_push_age_hours > 24)

    return {
        "path": str(repo_path),
        "name": repo_path.name,
        "branch": branch if ok_branch else "unknown",
        "upstream": upstream if ok_upstream else None,
        "ahead": ahead,
        "behind": behind,
        "dirty_count": dirty_count,
        "dirty_files": dirty_files[:8],
        "last_push_at": last_push_at,
        "last_push_age_hours": last_push_age_hours,
        "stale_uncommitted": stale_uncommitted,
        "status": status,
        "in_sync": status == "synced",
    }


def _repos_status_data() -> dict:
    repos = []
    workspaces = []
    if not WORKSPACES_ROOT.exists():
        return {
            "path": str(WORKSPACES_ROOT),
            "repos": [],
            "workspaces": [],
            "summary": {"total": 0, "synced": 0, "unsynced": 0},
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    for entry in WORKSPACES_ROOT.iterdir():
        if entry.is_dir() and not entry.name.startswith("."):
            workspaces.append(entry)

    for workspace in workspaces:
        repos_root = workspace / "data" / "repos"
        if not repos_root.exists() or not repos_root.is_dir():
            continue
        for repo_dir in repos_root.iterdir():
            if not repo_dir.is_dir() or repo_dir.name.startswith("."):
                continue
            if not (repo_dir / ".git").exists():
                continue
            repo_info = _repo_git_status(repo_dir)
            repo_info["workspace"] = workspace.name
            repos.append(repo_info)

    repos.sort(key=lambda item: (item.get("workspace", ""), item.get("name", "")))
    synced = sum(1 for repo in repos if repo.get("in_sync"))
    unsynced = len(repos) - synced

    return {
        "path": str(WORKSPACES_ROOT),
        "repos": repos,
        "workspaces": sorted([workspace.name for workspace in workspaces]),
        "summary": {"total": len(repos), "synced": synced, "unsynced": unsynced},
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _mapping_data() -> dict:
    config = _json_or_none(OPENCLAW_CONFIG_PATH)
    if not isinstance(config, dict):
        return {
            "default_workspace": "",
            "channels": {},
            "agents": [],
            "bindings": [],
            "signal": {"contacts": [], "groups": [], "contact_count": 0, "group_count": 0},
            "masked_auth": {},
        }

    masked = _mask_sensitive(config)
    if not isinstance(masked, dict):
        return {
            "default_workspace": "",
            "channels": {},
            "agents": [],
            "bindings": [],
            "signal": {"contacts": [], "groups": [], "contact_count": 0, "group_count": 0},
            "masked_auth": {},
        }
    agents = masked.get("agents")
    if not isinstance(agents, dict):
        agents = {}

    defaults = agents.get("defaults")
    if not isinstance(defaults, dict):
        defaults = {}

    channels = masked.get("channels")
    if not isinstance(channels, dict):
        channels = {}

    signal_channel = channels.get("signal")
    if not isinstance(signal_channel, dict):
        signal_channel = {}
    signal_contacts = []
    signal_groups = []
    signal_bindings = []

    for entry in signal_channel.get("allowFrom", []):
        if isinstance(entry, str) and entry not in signal_contacts:
            signal_contacts.append(entry)
    for entry in signal_channel.get("groupAllowFrom", []):
        if isinstance(entry, str) and entry not in signal_contacts:
            signal_contacts.append(entry)

    for binding in masked.get("bindings", []):
        if not isinstance(binding, dict):
            continue
        agent_id = binding.get("agentId") if isinstance(binding.get("agentId"), str) else ""
        match = binding.get("match", {})
        if not isinstance(match, dict) or match.get("channel") != "signal":
            continue
        peer = match.get("peer", {})
        if not isinstance(peer, dict):
            continue
        peer_id = peer.get("id")
        peer_kind = peer.get("kind")
        if not isinstance(peer_id, str):
            continue
        if peer_kind == "group":
            if peer_id not in signal_groups:
                signal_groups.append(peer_id)
            signal_bindings.append(
                {
                    "agent_id": agent_id,
                    "target_kind": "group",
                    "target_id": peer_id,
                    "source": "binding",
                }
            )
        else:
            if peer_id not in signal_contacts:
                signal_contacts.append(peer_id)
            signal_bindings.append(
                {
                    "agent_id": agent_id,
                    "target_kind": "contact",
                    "target_id": peer_id,
                    "source": "binding",
                }
            )

    agent_ids = []
    for agent in agents.get("list", []):
        if not isinstance(agent, dict):
            continue
        agent_id = agent.get("id")
        if isinstance(agent_id, str) and agent_id and agent_id not in agent_ids:
            agent_ids.append(agent_id)

    bound_agents = {
        row.get("agent_id")
        for row in signal_bindings
        if isinstance(row, dict) and isinstance(row.get("agent_id"), str) and row.get("agent_id")
    }
    if "main" not in bound_agents and "main" not in agent_ids:
        agent_ids.insert(0, "main")

    for agent_id in agent_ids:
        if agent_id in bound_agents:
            continue
        for contact in signal_contacts:
            signal_bindings.append(
                {
                    "agent_id": agent_id,
                    "target_kind": "contact",
                    "target_id": contact,
                    "source": "fallback_dm",
                }
            )

    deduped_signal_bindings = []
    seen_bindings = set()
    for row in signal_bindings:
        if not isinstance(row, dict):
            continue
        key = (row.get("agent_id"), row.get("target_kind"), row.get("target_id"), row.get("source"))
        if key in seen_bindings:
            continue
        seen_bindings.add(key)
        deduped_signal_bindings.append(row)

    return {
        "default_workspace": defaults.get("workspace", "") if isinstance(defaults, dict) else "",
        "channels": channels,
        "agents": agents.get("list", []) if isinstance(agents, dict) else [],
        "bindings": masked.get("bindings", []),
        "sessions": _openclaw_starters_data().get("sessions", []),
        "signal": {
            "contacts": signal_contacts,
            "groups": signal_groups,
            "contact_count": len(signal_contacts),
            "group_count": len(signal_groups),
        },
        "signal_bindings": deduped_signal_bindings,
        "masked_auth": masked.get("auth", {}),
    }


def _render_workspace_readme() -> tuple[str, str]:
    if not README_PATH.exists():
        return (
            "README not found",
            f"{README_PATH} does not exist.",
        )

    raw = README_PATH.read_text(encoding="utf-8", errors="replace")
    return "Workspace README", md.render(raw)


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if is_authenticated(request):
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, password: str = Form(...)):
    if password != _password():
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid password."},
            status_code=401,
        )

    response = RedirectResponse(url="/", status_code=303)
    expires = datetime.now(timezone.utc) + timedelta(days=365 * 20)
    token = serializer.dumps({"password_hash": _password_hash()})
    response.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=60 * 60 * 24 * 365 * 20,
        expires=expires,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(),
    )
    return response


@app.post("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie(AUTH_COOKIE)
    return response


@app.get("/api/status")
def api_status(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _system_status()


@app.get("/api/system-resources")
def api_system_resources(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _system_status()


@app.get("/api/openclaw-starters")
def api_openclaw_starters(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _openclaw_starters_data()


@app.get("/api/usage-stats")
def api_usage_stats(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _usage_stats_data()


@app.get("/api/settings")
def api_settings(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _settings_data()


@app.get("/api/stt-status")
def api_stt_status(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _stt_status_data()


@app.get("/api/crons")
def api_crons(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _cron_jobs_data()


@app.get("/api/mapping")
def api_mapping(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _mapping_data()


@app.get("/api/workspaces-sync")
def api_workspaces_sync(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _workspaces_sync_data()


@app.get("/api/repos-status")
def api_repos_status(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _repos_status_data()


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    blocked = require_auth(request)
    if blocked:
        return blocked

    readme_title, readme_html = _render_workspace_readme()
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "readme_title": readme_title,
            "readme_html": readme_html,
            "status": _system_status(),
        },
    )
