import hashlib
import json
import os
import subprocess
import threading
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
OPENCLAW_CONFIG_PATH = Path(os.path.expanduser("~/.openclaw/openclaw.json"))
OPENCLAW_CRON_PATH = Path(os.path.expanduser("~/.openclaw/cron/jobs.json"))
OPENCLAW_AGENTS_DIR = Path(os.path.expanduser("~/.openclaw/agents"))
CLAUDE_CREDENTIALS_PATH = Path(os.path.expanduser("~/.claude/.credentials.json"))
CLAUDE_STATS_PATH = Path(os.path.expanduser("~/.claude/stats-cache.json"))
DEFAULT_REPOS_ROOT = Path("/root/git")
LEGACY_WORKSPACES_ROOT = Path("/root/workspaces")
DEFAULT_README_PATH = LEGACY_WORKSPACES_ROOT / "README.md"
HOOKER_TARGETS_PATH = Path(os.path.expanduser("~/.openclaw/clawq-notify-targets.json"))
MEMORY_SAVE_CONFIG_PATH = Path(os.path.expanduser("~/.openclaw/clawq-memory-save.json"))
HOOKER_SCAN_SECONDS = 5

REPO_HOOKER_LAST_HEADS: dict[str, str] = {}
MEMORY_HOOKER_LAST_HEAD = ""
REPO_HOOKER_EVENT_LOG: list[dict] = []
MEMORY_HOOKER_LAST_EVENT: dict | None = None
SIGNAL_GROUP_NAME_CACHE: dict = {"loaded_at": 0.0, "data": {}}
HOOKER_STATE_LOCK = threading.Lock()
MEMORY_SAVE_LOCK = threading.Lock()
HOOKER_THREAD_STARTED = False


def _env_path(name: str) -> Path | None:
    value = os.getenv(name, "").strip()
    if not value:
        return None
    return Path(os.path.expanduser(value))


def _has_direct_git_repos(path: Path) -> bool:
    if not path.is_dir():
        return False
    try:
        for entry in path.iterdir():
            if entry.is_dir() and not entry.name.startswith(".") and (entry / ".git").exists():
                return True
    except OSError:
        return False
    return False


def _resolve_repos_root() -> Path:
    override = _env_path("CLAWQ_REPOS_ROOT")
    if override:
        return override

    if _has_direct_git_repos(DEFAULT_REPOS_ROOT):
        return DEFAULT_REPOS_ROOT

    if LEGACY_WORKSPACES_ROOT.exists():
        return LEGACY_WORKSPACES_ROOT

    return DEFAULT_REPOS_ROOT


WORKSPACES_ROOT = _resolve_repos_root()


def _resolve_readme_path() -> Path:
    override = _env_path("CLAWQ_README_PATH")
    if override:
        return override

    if DEFAULT_README_PATH.exists():
        return DEFAULT_README_PATH

    return WORKSPACES_ROOT / "README.md"


README_PATH = _resolve_readme_path()


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
        "repos_root": str(WORKSPACES_ROOT),
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


def _run_git(cwd: Path, *args: str, timeout_seconds: int = 6) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except Exception:
        return False, ""

    if completed.returncode != 0:
        return False, completed.stderr.strip() or completed.stdout.strip()
    return True, completed.stdout.strip()


def _memory_save_mode(value: str | None) -> str:
    if value == "daily_23":
        return "daily_23"
    return "never"


def _memory_save_config() -> dict:
    raw = _json_or_none(MEMORY_SAVE_CONFIG_PATH)
    if not isinstance(raw, dict):
        raw = {}

    mode_raw = raw.get("mode") if isinstance(raw.get("mode"), str) else None
    last_auto_day = raw.get("last_auto_day") if isinstance(raw.get("last_auto_day"), str) else ""
    last_result = raw.get("last_result") if isinstance(raw.get("last_result"), dict) else {}
    return {
        "mode": _memory_save_mode(mode_raw),
        "last_auto_day": last_auto_day,
        "last_result": last_result,
    }


def _write_memory_save_config(config: dict) -> None:
    payload = {
        "mode": _memory_save_mode(config.get("mode") if isinstance(config, dict) else None),
        "last_auto_day": str(config.get("last_auto_day") or "") if isinstance(config, dict) else "",
        "last_result": config.get("last_result") if isinstance(config.get("last_result"), dict) else {},
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }

    try:
        MEMORY_SAVE_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        MEMORY_SAVE_CONFIG_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        return


def _memory_save_config_data() -> dict:
    config = _memory_save_config()
    mode = _memory_save_mode(config.get("mode") if isinstance(config, dict) else None)
    return {
        "mode": mode,
        "options": [
            {"value": "never", "label": "Nie"},
            {"value": "daily_23", "label": "1x täglich (23:00)"},
        ],
        "last_auto_day": config.get("last_auto_day", ""),
        "last_result": config.get("last_result", {}),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _set_memory_save_mode(mode: str | None) -> dict:
    config = _memory_save_config()
    config["mode"] = _memory_save_mode(mode)
    _write_memory_save_config(config)
    return _memory_save_config_data()


def _record_memory_save_result(result: dict, reason: str) -> None:
    config = _memory_save_config()
    config["last_result"] = {
        "ok": bool(result.get("ok")),
        "status": str(result.get("status") or "unknown"),
        "reason": reason,
        "checked_at": str(result.get("checked_at") or datetime.now(timezone.utc).isoformat()),
    }
    if reason == "auto_daily_23":
        config["last_auto_day"] = datetime.now().date().isoformat()
    _write_memory_save_config(config)


def _memory_commit_message(reason: str) -> str:
    if reason == "auto_daily_23":
        return "chore(memory): daily autosave"
    return "chore(memory): save workspace memory"


def _memory_save_now(reason: str = "manual") -> dict:
    checked_at = datetime.now(timezone.utc).isoformat()

    with MEMORY_SAVE_LOCK:
        repo_root = _resolve_memory_repo_root()
        if not repo_root:
            return {
                "ok": False,
                "status": "not_git_repo",
                "repo_path": None,
                "dirty_before": 0,
                "committed": False,
                "pushed": False,
                "reason": reason,
                "checked_at": checked_at,
                "error": "Memory repository not found",
            }

        ok_repo, _ = _run_git(repo_root, "rev-parse", "--is-inside-work-tree")
        if not ok_repo:
            return {
                "ok": False,
                "status": "not_git_repo",
                "repo_path": str(repo_root),
                "dirty_before": 0,
                "committed": False,
                "pushed": False,
                "reason": reason,
                "checked_at": checked_at,
                "error": "Target path is not a git repository",
            }

        ok_status, porcelain = _run_git(repo_root, "status", "--porcelain")
        dirty_files = []
        if ok_status and porcelain:
            for line in porcelain.splitlines():
                if len(line) >= 4:
                    dirty_files.append(line[3:].strip())

        dirty_before = len(dirty_files)
        committed = False
        commit_head = None
        commit_message = None

        if dirty_before > 0:
            ok_add, add_out = _run_git(repo_root, "add", "-A", timeout_seconds=20)
            if not ok_add:
                return {
                    "ok": False,
                    "status": "add_failed",
                    "repo_path": str(repo_root),
                    "dirty_before": dirty_before,
                    "committed": False,
                    "pushed": False,
                    "reason": reason,
                    "checked_at": checked_at,
                    "error": add_out,
                }

            commit_message = _memory_commit_message(reason)
            ok_commit, commit_out = _run_git(repo_root, "commit", "-m", commit_message, timeout_seconds=30)
            if not ok_commit:
                lower = commit_out.lower()
                if "nothing to commit" not in lower and "no changes added" not in lower:
                    return {
                        "ok": False,
                        "status": "commit_failed",
                        "repo_path": str(repo_root),
                        "dirty_before": dirty_before,
                        "committed": False,
                        "pushed": False,
                        "reason": reason,
                        "checked_at": checked_at,
                        "error": commit_out,
                    }
            else:
                committed = True
                ok_head, head_out = _run_git(repo_root, "rev-parse", "--short", "HEAD")
                if ok_head and head_out:
                    commit_head = head_out

        ok_push, push_out = _run_git(repo_root, "push", timeout_seconds=45)
        if not ok_push:
            return {
                "ok": False,
                "status": "push_failed",
                "repo_path": str(repo_root),
                "dirty_before": dirty_before,
                "committed": committed,
                "commit_head": commit_head,
                "commit_message": commit_message,
                "pushed": False,
                "reason": reason,
                "checked_at": checked_at,
                "error": push_out,
            }

        return {
            "ok": True,
            "status": "committed_and_pushed" if committed else "pushed",
            "repo_path": str(repo_root),
            "dirty_before": dirty_before,
            "committed": committed,
            "commit_head": commit_head,
            "commit_message": commit_message,
            "pushed": True,
            "reason": reason,
            "checked_at": checked_at,
            "sync": _workspaces_sync_data(),
        }


def _run_memory_autosave_if_due() -> None:
    config = _memory_save_config()
    if config.get("mode") != "daily_23":
        return

    now = datetime.now()
    today = now.date().isoformat()
    if now.hour != 23:
        return
    if config.get("last_auto_day") == today:
        return

    result = _memory_save_now(reason="auto_daily_23")
    _record_memory_save_result(result, reason="auto_daily_23")


def _workspaces_sync_data() -> dict:
    checked_at = datetime.now(timezone.utc).isoformat()

    memory_repo_root = _resolve_memory_repo_root()
    if not memory_repo_root:
        candidate = README_PATH.parent if README_PATH.parent.exists() else LEGACY_WORKSPACES_ROOT
        return {
            "path": str(candidate),
            "exists": candidate.exists(),
            "is_git_repo": False,
            "in_sync": False,
            "status": "not_git_repo",
            "checked_at": checked_at,
        }

    ok_branch, branch = _run_git(memory_repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    ok_upstream, upstream = _run_git(memory_repo_root, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    ok_status, porcelain = _run_git(memory_repo_root, "status", "--porcelain")

    dirty_files = []
    if ok_status and porcelain:
        for line in porcelain.splitlines():
            if len(line) >= 4:
                dirty_files.append(line[3:].strip())

    ahead = 0
    behind = 0
    if ok_upstream:
        ok_counts, counts = _run_git(memory_repo_root, "rev-list", "--left-right", "--count", "@{upstream}...HEAD")
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
        "path": str(memory_repo_root),
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
        "checked_at": checked_at,
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


def _discover_repo_dirs() -> tuple[list[tuple[str, Path]], list[str]]:
    discovered: list[tuple[str, Path]] = []
    workspace_names: set[str] = set()
    seen_paths: set[str] = set()

    try:
        entries = [entry for entry in WORKSPACES_ROOT.iterdir() if entry.is_dir() and not entry.name.startswith(".")]
    except OSError:
        return discovered, []

    for workspace in entries:
        repos_root = workspace / "data" / "repos"
        if not repos_root.is_dir():
            continue
        workspace_names.add(workspace.name)
        try:
            repo_dirs = [repo_dir for repo_dir in repos_root.iterdir() if repo_dir.is_dir() and not repo_dir.name.startswith(".")]
        except OSError:
            continue
        for repo_dir in repo_dirs:
            if not (repo_dir / ".git").exists():
                continue
            key = str(repo_dir)
            if key in seen_paths:
                continue
            seen_paths.add(key)
            discovered.append((workspace.name, repo_dir))

    flat_workspace = WORKSPACES_ROOT.name or "root"
    for repo_dir in entries:
        if not (repo_dir / ".git").exists():
            continue
        key = str(repo_dir)
        if key in seen_paths:
            continue
        seen_paths.add(key)
        workspace_names.add(flat_workspace)
        discovered.append((flat_workspace, repo_dir))

    return discovered, sorted(workspace_names)


def _repo_head_snapshot(repo_path: Path) -> dict | None:
    ok_head, head = _run_git(repo_path, "rev-parse", "HEAD")
    if not ok_head or not head:
        return None

    ok_branch, branch = _run_git(repo_path, "rev-parse", "--abbrev-ref", "HEAD")
    ok_subject, subject = _run_git(repo_path, "log", "-1", "--format=%s")
    ok_commit_ts, commit_ts = _run_git(repo_path, "log", "-1", "--format=%ct")

    committed_at = None
    if ok_commit_ts and commit_ts.isdigit():
        committed_at = datetime.fromtimestamp(int(commit_ts), tz=timezone.utc).isoformat()

    return {
        "path": str(repo_path),
        "name": repo_path.name,
        "branch": branch if ok_branch else "unknown",
        "head": head,
        "head_short": head[:8],
        "subject": subject if ok_subject else "",
        "committed_at": committed_at,
    }


def _signal_bindings_map() -> dict[str, str]:
    config = _json_or_none(OPENCLAW_CONFIG_PATH)
    if not isinstance(config, dict):
        return {}

    bindings = {}
    for row in config.get("bindings", []):
        if not isinstance(row, dict):
            continue
        agent_id = row.get("agentId")
        match = row.get("match")
        if not isinstance(agent_id, str) or not isinstance(match, dict):
            continue
        if match.get("channel") != "signal":
            continue
        peer = match.get("peer")
        if not isinstance(peer, dict) or peer.get("kind") != "group":
            continue
        group_id = peer.get("id")
        if isinstance(group_id, str) and group_id:
            bindings[agent_id] = group_id
    return bindings


def _signal_channel_settings() -> dict:
    config = _json_or_none(OPENCLAW_CONFIG_PATH)
    if not isinstance(config, dict):
        return {"enabled": False, "account": ""}

    signal_cfg = config.get("channels", {}).get("signal", {})
    if not isinstance(signal_cfg, dict):
        signal_cfg = {}

    return {
        "enabled": bool(signal_cfg.get("enabled", False)),
        "account": str(signal_cfg.get("account", "") or ""),
    }


def _mask_group_id(group_id: str | None) -> str | None:
    if not group_id:
        return None
    if len(group_id) <= 12:
        return group_id
    return f"{group_id[:6]}...{group_id[-4:]}"


def _mask_contact_id(contact: str | None) -> str | None:
    if not contact:
        return None
    if len(contact) <= 8:
        return contact
    return f"{contact[:4]}...{contact[-2:]}"


def _canonical_group_id(value: str) -> str:
    group_id = value.strip()
    if group_id.startswith("group:"):
        group_id = group_id.split(":", 1)[1]
    return group_id.lower()


def _looks_like_encoded_group(text: str) -> bool:
    value = text.strip()
    if not value:
        return False
    if any(char in value for char in ["+", "/", "="]):
        return True

    compact = value.replace(" ", "")
    if len(compact) >= 24:
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        if all(char in allowed for char in compact) and sum(char.isdigit() for char in compact) >= 4:
            return True

    if value.lower().startswith("group "):
        tail = value[6:].replace(" ", "")
        if len(tail) >= 20 and sum(char.isdigit() for char in tail) >= 4:
            return True

    return False


def _signal_group_subjects_map() -> dict[str, str]:
    global SIGNAL_GROUP_NAME_CACHE

    now = time.time()
    with HOOKER_STATE_LOCK:
        cached = SIGNAL_GROUP_NAME_CACHE.get("data", {}) if isinstance(SIGNAL_GROUP_NAME_CACHE, dict) else {}
        loaded_at = float(SIGNAL_GROUP_NAME_CACHE.get("loaded_at", 0.0)) if isinstance(SIGNAL_GROUP_NAME_CACHE, dict) else 0.0
        if isinstance(cached, dict) and now - loaded_at < 60:
            return dict(cached)

    group_names: dict[str, str] = {}

    for sessions_path in OPENCLAW_AGENTS_DIR.glob("*/sessions/sessions.json"):
        sessions = _json_or_none(sessions_path)
        if not isinstance(sessions, dict):
            continue

        for row in sessions.values():
            if not isinstance(row, dict):
                continue

            origin_value = row.get("origin")
            origin = origin_value if isinstance(origin_value, dict) else {}

            group_value = row.get("groupId") if isinstance(row.get("groupId"), str) else ""
            if not group_value and origin:
                from_raw = origin.get("from")
                to_raw = origin.get("to")
                from_value = from_raw if isinstance(from_raw, str) else ""
                to_value = to_raw if isinstance(to_raw, str) else ""
                group_value = from_value if from_value.startswith("group:") else to_value
            if not group_value:
                continue

            subject_raw = row.get("subject")
            subject = subject_raw if isinstance(subject_raw, str) else ""
            subject = subject.strip()
            if not subject and origin:
                label = origin.get("label") if isinstance(origin.get("label"), str) else ""
                if isinstance(label, str) and " id:" in label:
                    subject = label.split(" id:", 1)[0].strip()
            if not subject:
                display_raw = row.get("displayName")
                display_name = display_raw if isinstance(display_raw, str) else ""
                if display_name.startswith("signal:g-"):
                    display_subject = display_name.split("signal:g-", 1)[1].strip()
                    if display_subject and not _looks_like_encoded_group(display_subject):
                        subject = display_subject.replace("-", " ").strip().title()
            if subject and _looks_like_encoded_group(subject):
                subject = ""
            if not subject:
                continue

            canonical = _canonical_group_id(group_value)
            if canonical and canonical not in group_names:
                group_names[canonical] = subject

    with HOOKER_STATE_LOCK:
        SIGNAL_GROUP_NAME_CACHE = {"loaded_at": now, "data": dict(group_names)}

    return group_names


def _signal_main_contact() -> str | None:
    config = _json_or_none(OPENCLAW_CONFIG_PATH)
    if not isinstance(config, dict):
        return None

    signal_cfg = config.get("channels", {}).get("signal", {})
    if not isinstance(signal_cfg, dict):
        return None

    allow_from = signal_cfg.get("allowFrom", [])
    if isinstance(allow_from, list):
        for entry in allow_from:
            if isinstance(entry, str) and entry.strip():
                return entry.strip()

    account = signal_cfg.get("account")
    if isinstance(account, str) and account.strip():
        return account.strip()
    return None


def _hooker_target_options() -> list[dict]:
    options = []
    seen_values = set()
    group_names = _signal_group_subjects_map()
    bindings_map = _signal_bindings_map()

    group_agents: dict[str, list[str]] = {}
    for agent_id, group_id in bindings_map.items():
        canonical = _canonical_group_id(group_id)
        if canonical not in group_agents:
            group_agents[canonical] = []
        if agent_id not in group_agents[canonical]:
            group_agents[canonical].append(agent_id)

    main_contact = _signal_main_contact()
    if main_contact:
        value = f"contact:{main_contact}"
        options.append(
            {
                "value": value,
                "label": f"Hauptkontakt {_mask_contact_id(main_contact)}",
                "kind": "contact",
            }
        )
        seen_values.add(value)

    group_ids = sorted(set(bindings_map.values()))
    for group_id in group_ids:
        value = f"group:{group_id}"
        if value in seen_values:
            continue

        canonical = _canonical_group_id(group_id)
        group_name = group_names.get(canonical, "").strip()
        agents_hint = ", ".join(group_agents.get(canonical, [])[:2])

        if group_name:
            label = f"{group_name} ({_mask_group_id(group_id)})"
        elif agents_hint:
            label = f"Signal {agents_hint} ({_mask_group_id(group_id)})"
        else:
            label = f"Signal Gruppe {_mask_group_id(group_id)}"

        options.append(
            {
                "value": value,
                "label": label,
                "kind": "group",
            }
        )
        seen_values.add(value)

    return options


def _notification_targets_data() -> dict:
    options = _hooker_target_options()
    allowed_values = {row.get("value") for row in options if isinstance(row, dict)}

    stored = _json_or_none(HOOKER_TARGETS_PATH)
    if not isinstance(stored, dict):
        stored = {}

    default_target = options[0]["value"] if options else None
    memory_target = stored.get("memory_target") if stored.get("memory_target") in allowed_values else default_target

    repo_overrides = {}
    raw_repo_overrides = stored.get("repo_overrides")
    if isinstance(raw_repo_overrides, dict):
        for repo_key, target_value in raw_repo_overrides.items():
            if not isinstance(repo_key, str) or not isinstance(target_value, str):
                continue
            if target_value not in allowed_values:
                continue
            repo_overrides[repo_key] = target_value

    return {
        "options": options,
        "memory_target": memory_target,
        "default_target": default_target,
        "repo_overrides": repo_overrides,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


def _target_meta(target_value: str | None) -> dict:
    return {
        "value": target_value,
        "label": _target_label_for_value(target_value),
    }


def _write_notification_targets(memory_target: str | None, repo_overrides: dict[str, str]) -> None:
    payload = {
        "memory_target": memory_target,
        "repo_overrides": repo_overrides,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    try:
        HOOKER_TARGETS_PATH.parent.mkdir(parents=True, exist_ok=True)
        HOOKER_TARGETS_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        return


def _set_notification_targets(memory_target: str | None = None) -> dict:
    current = _notification_targets_data()
    options = current.get("options", []) if isinstance(current, dict) else []
    allowed_values = {row.get("value") for row in options if isinstance(row, dict)}

    next_memory = current.get("memory_target")
    next_overrides = current.get("repo_overrides", {}) if isinstance(current.get("repo_overrides"), dict) else {}

    if isinstance(memory_target, str) and memory_target in allowed_values:
        next_memory = memory_target

    _write_notification_targets(next_memory, next_overrides)
    return _notification_targets_data()


def _set_repo_notification_target(repo_path: str, target_value: str | None) -> dict:
    repo_key = repo_path.strip()
    if not repo_key:
        return _notification_targets_data()

    current = _notification_targets_data()
    options = current.get("options", []) if isinstance(current, dict) else []
    allowed_values = {row.get("value") for row in options if isinstance(row, dict)}
    next_memory = current.get("memory_target")
    next_overrides = dict(current.get("repo_overrides", {}) if isinstance(current.get("repo_overrides"), dict) else {})

    if target_value in {None, "", "default", "__default__"}:
        next_overrides.pop(repo_key, None)
    elif isinstance(target_value, str) and target_value in allowed_values:
        next_overrides[repo_key] = target_value

    _write_notification_targets(next_memory, next_overrides)
    return _notification_targets_data()


def _repo_target_for_path(repo_path: str, targets: dict) -> tuple[str | None, bool]:
    default_target = targets.get("default_target") if isinstance(targets, dict) else None
    repo_overrides = targets.get("repo_overrides") if isinstance(targets, dict) else None
    if isinstance(repo_overrides, dict):
        value = repo_overrides.get(repo_path)
        if isinstance(value, str):
            return value, False
    return default_target, True


def _parse_signal_target(target_value: str | None) -> tuple[str, str] | None:
    if not isinstance(target_value, str) or ":" not in target_value:
        return None
    kind, target_id = target_value.split(":", 1)
    kind = kind.strip().lower()
    target_id = target_id.strip()
    if kind not in {"group", "contact"} or not target_id:
        return None
    return kind, target_id


def _target_label_for_value(target_value: str | None) -> str:
    parsed = _parse_signal_target(target_value)
    if not parsed:
        return "Kein Ziel"
    kind, target_id = parsed
    if kind == "group":
        canonical = _canonical_group_id(target_id)
        group_name = _signal_group_subjects_map().get(canonical, "").strip()
        if group_name:
            return f"{group_name} ({_mask_group_id(target_id)})"
        bindings = _signal_bindings_map()
        agent_hints = [agent for agent, group_id in bindings.items() if _canonical_group_id(group_id) == canonical]
        if agent_hints:
            return f"Signal {agent_hints[0]} ({_mask_group_id(target_id)})"
        return f"Signal Gruppe {_mask_group_id(target_id)}"
    return f"Hauptkontakt {_mask_contact_id(target_id)}"


def _mask_target_value(target_value: str | None) -> str | None:
    parsed = _parse_signal_target(target_value)
    if not parsed:
        return None
    kind, target_id = parsed
    if kind == "group":
        return f"group:{_mask_group_id(target_id)}"
    return f"contact:{_mask_contact_id(target_id)}"


def _effective_signal_target(target_value: str | None) -> str | None:
    if _parse_signal_target(target_value):
        return target_value

    targets = _notification_targets_data()
    default_target = targets.get("default_target") if isinstance(targets, dict) else None
    if isinstance(default_target, str) and _parse_signal_target(default_target):
        return default_target

    main_contact = _signal_main_contact()
    if main_contact:
        return f"contact:{main_contact}"

    return None


def _remote_commit_url(repo_path: Path, head: str) -> str | None:
    ok_remote, remote = _run_git(repo_path, "remote", "get-url", "origin")
    if not ok_remote or not remote:
        return None

    cleaned = remote.strip()
    if cleaned.startswith("git@"):
        host_path = cleaned.split("@", 1)[1]
        if ":" not in host_path:
            return None
        host, path = host_path.split(":", 1)
        cleaned = f"https://{host}/{path}"
    elif cleaned.startswith("ssh://git@"):
        host_path = cleaned.split("ssh://git@", 1)[1]
        if "/" not in host_path:
            return None
        host, path = host_path.split("/", 1)
        cleaned = f"https://{host}/{path}"
    elif cleaned.startswith("http://"):
        cleaned = f"https://{cleaned[7:]}"

    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]

    if not cleaned.startswith("https://"):
        return None
    return f"{cleaned}/commit/{head}"


def _commit_numstat(repo_path: Path, head: str) -> dict:
    ok_numstat, output = _run_git(repo_path, "show", "--numstat", "--format=", "--no-color", "--no-renames", head)
    if not ok_numstat:
        return {"files": [], "file_count": 0, "additions": 0, "deletions": 0}

    files = []
    additions_total = 0
    deletions_total = 0
    for line in output.splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        adds_raw, dels_raw = parts[0], parts[1]
        path = parts[2]
        additions = int(adds_raw) if adds_raw.isdigit() else 0
        deletions = int(dels_raw) if dels_raw.isdigit() else 0
        additions_total += additions
        deletions_total += deletions
        files.append(
            {
                "path": path,
                "additions": additions,
                "deletions": deletions,
            }
        )

    return {
        "files": files,
        "file_count": len(files),
        "additions": additions_total,
        "deletions": deletions_total,
    }


def _format_commit_notification(snapshot: dict, numstat: dict, commit_url: str | None) -> str:
    subject = str(snapshot.get("subject") or "(no subject)").replace("\n", " ").strip()
    repo_name = str(snapshot.get("name") or "repo").replace("`", "'")
    branch = str(snapshot.get("branch") or "unknown").replace("`", "'")

    file_rows = numstat.get("files", []) if isinstance(numstat, dict) else []
    rendered_files = []
    for row in file_rows[:3]:
        if not isinstance(row, dict):
            continue
        path = str(row.get("path") or "file").replace("```", "'''").strip()
        additions = int(row.get("additions") or 0)
        deletions = int(row.get("deletions") or 0)
        rendered_files.append(f"{path} (+{additions} -{deletions})")

    file_count = int(numstat.get("file_count") or 0) if isinstance(numstat, dict) else 0
    additions_total = int(numstat.get("additions") or 0) if isinstance(numstat, dict) else 0
    deletions_total = int(numstat.get("deletions") or 0) if isinstance(numstat, dict) else 0

    lines = [
        "🧠 *ClawQ Update*",
        f"*Commit:* {subject}",
        "─────",
        f"*Repo:* `{repo_name}/{branch}`",
        f"*Änderung:* `{file_count} files +{additions_total} -{deletions_total}`",
    ]

    if rendered_files:
        lines.append("")
        lines.append("```")
        lines.extend(rendered_files)
        lines.append("```")

    lines.append("─────")

    if commit_url:
        lines.append("")
        lines.append(f"🔗 *Link:* {commit_url}")
    else:
        head_short = str(snapshot.get("head_short") or "-").replace("`", "'")
        lines.append("")
        lines.append(f"*Head:* `{head_short}`")

    lines.append("")
    lines.append("✨ Viel Erfolg beim Weitermachen!")

    return "\n".join(lines)


def _send_signal_message(target_value: str | None, message: str) -> tuple[bool, str, str | None, str | None]:
    effective_target = _effective_signal_target(target_value)
    parsed = _parse_signal_target(effective_target)
    if not parsed:
        return False, "no_target", None, None
    target_kind, target_id = parsed

    signal_cfg = _signal_channel_settings()
    if not signal_cfg.get("enabled"):
        return False, "signal_channel_disabled", target_kind, None

    account = str(signal_cfg.get("account") or "").strip()
    if not account:
        return False, "missing_signal_account", target_kind, None

    target = f"group:{target_id}" if target_kind == "group" else target_id
    command = [
        "openclaw",
        "message",
        "send",
        "--channel",
        "signal",
        "--target",
        target,
        "--message",
        message,
        "--json",
    ]

    last_details = None
    for attempt in range(2):
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception as exc:
            last_details = str(exc)
            if attempt == 0:
                time.sleep(0.6)
                continue
            return False, "signal_send_failed", target_kind, last_details

        details = (completed.stderr or completed.stdout or "").strip()
        if completed.returncode == 0:
            return True, "sent", target_kind, None

        if "Unknown target" in details:
            return False, "invalid_target", target_kind, details

        last_details = details
        if attempt == 0:
            time.sleep(0.6)
            continue

    return False, "signal_send_failed", target_kind, last_details


def _build_commit_event(snapshot: dict, target_value: str | None) -> dict:
    repo_path = Path(str(snapshot.get("path", "")))
    head = str(snapshot.get("head") or "")
    numstat = _commit_numstat(repo_path, head) if head else {"files": [], "file_count": 0, "additions": 0, "deletions": 0}
    commit_url = _remote_commit_url(repo_path, head) if head else None
    message = _format_commit_notification(snapshot, numstat, commit_url)

    effective_target = _effective_signal_target(target_value)

    notify = {
        "sent": False,
        "status": "no_target",
        "target": _mask_target_value(effective_target),
        "target_label": _target_label_for_value(effective_target),
        "target_kind": None,
        "error": None,
    }
    sent, status, target_kind, error = _send_signal_message(effective_target, message)
    notify["sent"] = sent
    notify["status"] = status
    notify["target_kind"] = target_kind
    notify["error"] = error

    return {
        "repo": snapshot.get("name"),
        "workspace": snapshot.get("workspace"),
        "branch": snapshot.get("branch"),
        "head": head,
        "head_short": snapshot.get("head_short"),
        "subject": snapshot.get("subject"),
        "committed_at": snapshot.get("committed_at"),
        "url": commit_url,
        "message": message,
        "numstat": numstat,
        "notify": notify,
    }


def _repo_hooker_data() -> dict:
    global REPO_HOOKER_LAST_HEADS, REPO_HOOKER_EVENT_LOG

    checked_at = datetime.now(timezone.utc).isoformat()
    targets = _notification_targets_data()
    default_target = targets.get("default_target")
    raw_repo_overrides = targets.get("repo_overrides")
    repo_overrides: dict[str, str] = raw_repo_overrides if isinstance(raw_repo_overrides, dict) else {}

    if not WORKSPACES_ROOT.exists():
        return {
            "path": str(WORKSPACES_ROOT),
            "repos": [],
            "summary": {"total": 0},
            "events": [],
            "target_default": _target_meta(default_target),
            "repo_overrides_count": len(repo_overrides),
            "checked_at": checked_at,
        }

    discovered, _ = _discover_repo_dirs()
    repos = []
    for workspace_name, repo_dir in discovered:
        snapshot = _repo_head_snapshot(repo_dir)
        if not snapshot:
            continue
        snapshot["workspace"] = workspace_name

        target_value, is_default = _repo_target_for_path(str(snapshot.get("path", "")), targets)
        snapshot["notify_target"] = {
            "value": target_value,
            "label": _target_label_for_value(target_value),
            "is_default": is_default,
        }
        repos.append(snapshot)

    repos.sort(key=lambda item: (item.get("workspace", ""), item.get("name", "")))
    changed_snapshots = []
    current_heads = {}
    for snapshot in repos:
        repo_path = str(snapshot.get("path", ""))
        current_head = str(snapshot.get("head", ""))
        if repo_path and current_head:
            current_heads[repo_path] = current_head

    with HOOKER_STATE_LOCK:
        for snapshot in repos:
            repo_path = str(snapshot.get("path", ""))
            current_head = str(snapshot.get("head", ""))
            if not repo_path or not current_head:
                continue
            previous_head = REPO_HOOKER_LAST_HEADS.get(repo_path, "")
            if previous_head and previous_head != current_head:
                changed_snapshots.append(snapshot)
        REPO_HOOKER_LAST_HEADS = current_heads

    events = []
    for snapshot in changed_snapshots:
        notify_target = snapshot.get("notify_target") if isinstance(snapshot.get("notify_target"), dict) else {}
        events.append(_build_commit_event(snapshot, notify_target.get("value")))

    with HOOKER_STATE_LOCK:
        if events:
            REPO_HOOKER_EVENT_LOG = (events + REPO_HOOKER_EVENT_LOG)[:24]
        events_out = REPO_HOOKER_EVENT_LOG[:12]

    return {
        "path": str(WORKSPACES_ROOT),
        "repos": repos,
        "summary": {"total": len(repos)},
        "events": events_out,
        "target_default": _target_meta(default_target),
        "repo_overrides_count": len(repo_overrides),
        "checked_at": checked_at,
    }


def _resolve_memory_repo_root() -> Path | None:
    candidates = []
    if README_PATH.exists():
        candidates.append(README_PATH.parent)
    candidates.extend([LEGACY_WORKSPACES_ROOT, WORKSPACES_ROOT])

    seen = set()
    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        if not candidate.exists():
            continue

        ok_root, root = _run_git(candidate, "rev-parse", "--show-toplevel")
        if ok_root and root:
            return Path(root)

    return None


def _memory_hooker_data() -> dict:
    global MEMORY_HOOKER_LAST_HEAD, MEMORY_HOOKER_LAST_EVENT

    checked_at = datetime.now(timezone.utc).isoformat()
    targets = _notification_targets_data()
    selected_target = targets.get("memory_target")
    repo_root = _resolve_memory_repo_root()
    if not repo_root:
        return {
            "readme_path": str(README_PATH),
            "repo_path": None,
            "found": False,
            "reason": "not_git_repo",
            "event": MEMORY_HOOKER_LAST_EVENT,
            "target": _target_meta(selected_target),
            "checked_at": checked_at,
        }

    snapshot = _repo_head_snapshot(repo_root)
    if not snapshot:
        return {
            "readme_path": str(README_PATH),
            "repo_path": str(repo_root),
            "found": False,
            "reason": "no_head",
            "event": MEMORY_HOOKER_LAST_EVENT,
            "target": _target_meta(selected_target),
            "checked_at": checked_at,
        }

    current_head = str(snapshot.get("head", ""))
    has_change = False
    with HOOKER_STATE_LOCK:
        if MEMORY_HOOKER_LAST_HEAD and current_head and MEMORY_HOOKER_LAST_HEAD != current_head:
            has_change = True
        MEMORY_HOOKER_LAST_HEAD = current_head

    event = None
    if has_change:
        snapshot_for_event = dict(snapshot)
        snapshot_for_event["workspace"] = "memory"
        event = _build_commit_event(snapshot_for_event, selected_target)

    with HOOKER_STATE_LOCK:
        if event:
            MEMORY_HOOKER_LAST_EVENT = event
        last_event = MEMORY_HOOKER_LAST_EVENT

    return {
        "readme_path": str(README_PATH),
        "repo_path": str(repo_root),
        "found": True,
        "head": snapshot.get("head"),
        "head_short": snapshot.get("head_short"),
        "branch": snapshot.get("branch"),
        "subject": snapshot.get("subject"),
        "committed_at": snapshot.get("committed_at"),
        "event": last_event,
        "target": _target_meta(selected_target),
        "checked_at": checked_at,
    }


def _repos_status_data() -> dict:
    repos = []
    if not WORKSPACES_ROOT.exists():
        return {
            "path": str(WORKSPACES_ROOT),
            "repos": [],
            "workspaces": [],
            "summary": {"total": 0, "synced": 0, "unsynced": 0},
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

    discovered, workspaces = _discover_repo_dirs()
    for workspace_name, repo_dir in discovered:
        repo_info = _repo_git_status(repo_dir)
        repo_info["workspace"] = workspace_name
        repos.append(repo_info)

    repos.sort(key=lambda item: (item.get("workspace", ""), item.get("name", "")))
    synced = sum(1 for repo in repos if repo.get("in_sync"))
    unsynced = len(repos) - synced

    return {
        "path": str(WORKSPACES_ROOT),
        "repos": repos,
        "workspaces": workspaces,
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

    # Resolve group names for bindings
    group_names = _signal_group_subjects_map()
    for row in deduped_signal_bindings:
        if row.get("target_kind") == "group":
            canonical = _canonical_group_id(row.get("target_id", ""))
            name = group_names.get(canonical, "")
            if name:
                row["target_name"] = name

    # Resolve contact names from signal-cli recipient DB
    contact_names: dict[str, str] = {}
    try:
        import sqlite3 as _sqlite3
        _db_path = Path.home() / ".local/share/signal-cli/data"
        _account_json = _db_path / "accounts.json"
        if _account_json.exists():
            _accounts = json.loads(_account_json.read_text())
            _account_path = None
            _signal_account = signal_channel.get("account", "")
            for _acc in _accounts.get("accounts", []):
                if _acc.get("number") == _signal_account:
                    _account_path = _acc.get("path")
                    break
            if _account_path:
                _db_file = _db_path / f"{_account_path}.d" / "account.db"
                if _db_file.exists():
                    _conn = _sqlite3.connect(str(_db_file), timeout=2)
                    try:
                        for _row in _conn.execute("SELECT number, aci, profile_given_name, profile_family_name FROM recipient WHERE profile_given_name IS NOT NULL"):
                            _number, _aci, _given, _family = _row
                            _display = f"{_given or ''} {_family or ''}".strip()
                            if _display:
                                if _number:
                                    contact_names[_number] = _display
                                if _aci:
                                    contact_names[_aci] = _display
                                    contact_names[f"uuid:{_aci}"] = _display
                    finally:
                        _conn.close()
    except Exception:
        pass

    # Build security assessment
    dm_policy = signal_channel.get("dmPolicy", "pairing")
    group_policy = signal_channel.get("groupPolicy", "allowlist")
    allow_from_list = signal_channel.get("allowFrom", [])
    group_allow_from_list = signal_channel.get("groupAllowFrom", [])

    security_issues: list[dict] = []
    security_ok: list[str] = []

    if dm_policy == "disabled":
        security_ok.append("DMs deaktiviert")
    elif dm_policy == "allowlist":
        dm_labels = []
        for entry in allow_from_list:
            name = contact_names.get(entry, "")
            dm_labels.append(f"{name} ({entry})" if name else entry)
        security_ok.append(f"DMs nur für: {', '.join(dm_labels)}")
    elif dm_policy == "open":
        security_issues.append({"level": "warn", "text": "DMs offen für jeden!"})
    elif dm_policy == "pairing":
        security_ok.append("DMs nur mit Pairing-Code")

    if group_policy == "disabled":
        security_ok.append("Gruppen deaktiviert")
    elif group_policy == "allowlist":
        bound_groups = len([b for b in deduped_signal_bindings if b.get("source") == "binding" and b.get("target_kind") == "group"])
        security_ok.append(f"Nur {bound_groups} erlaubte Gruppe(n)")
    elif group_policy == "open":
        security_issues.append({"level": "warn", "text": "Bot reagiert in JEDER Gruppe!"})

    has_wildcard = "*" in group_allow_from_list
    if has_wildcard:
        security_issues.append({"level": "info", "text": "groupAllowFrom: * — jeder in erlaubten Gruppen kann schreiben"})
    elif group_allow_from_list:
        # Group entries by resolved name to avoid duplicates like "Lina (phone)" + "Lina (uuid)"
        _name_to_ids: dict[str, list[str]] = {}
        for entry in group_allow_from_list:
            name = contact_names.get(entry, "")
            key = name if name else entry
            _name_to_ids.setdefault(key, []).append(entry)
        sender_labels = []
        for key, ids in _name_to_ids.items():
            if key == ids[0]:
                # No name resolved — show raw id
                sender_labels.append(key)
            else:
                sender_labels.append(key)
        unique_count = len(_name_to_ids)
        security_ok.append(f"{unique_count} erlaubte Sender in Gruppen: {', '.join(sender_labels)}")

    security_score = "🟢 Sicher" if not security_issues else ("🟡 Hinweise" if all(i["level"] == "info" for i in security_issues) else "🔴 Unsicher")

    # Annotate allowFrom/groupAllowFrom with contact names
    allow_from_annotated = []
    for entry in allow_from_list:
        name = contact_names.get(entry, "")
        allow_from_annotated.append({"id": entry, "name": name})

    group_allow_from_annotated = []
    for entry in group_allow_from_list:
        name = contact_names.get(entry, "")
        group_allow_from_annotated.append({"id": entry, "name": name})

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
            "dmPolicy": dm_policy,
            "groupPolicy": group_policy,
            "allowFrom": allow_from_list,
            "groupAllowFrom": group_allow_from_list,
            "allowFromAnnotated": allow_from_annotated,
            "groupAllowFromAnnotated": group_allow_from_annotated,
        },
        "signal_bindings": deduped_signal_bindings,
        "masked_auth": masked.get("auth", {}),
        "security": {
            "score": security_score,
            "issues": security_issues,
            "ok": security_ok,
        },
    }


def _render_workspace_readme() -> tuple[str, str]:
    if not README_PATH.exists():
        return (
            "README not found",
            f"{README_PATH} does not exist.",
        )

    raw = README_PATH.read_text(encoding="utf-8", errors="replace")
    return "Workspace README", md.render(raw)


def _hooker_background_loop() -> None:
    while True:
        try:
            _repo_hooker_data()
            _memory_hooker_data()
            _run_memory_autosave_if_due()
        except Exception:
            pass
        time.sleep(HOOKER_SCAN_SECONDS)


@app.on_event("startup")
def startup_hooker_loop():
    global HOOKER_THREAD_STARTED
    with HOOKER_STATE_LOCK:
        if HOOKER_THREAD_STARTED:
            return
        worker = threading.Thread(target=_hooker_background_loop, daemon=True, name="clawq-hooker-loop")
        worker.start()
        HOOKER_THREAD_STARTED = True


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


@app.get("/api/repo-hooker")
def api_repo_hooker(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _repo_hooker_data()


@app.get("/api/memory-hooker")
def api_memory_hooker(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _memory_hooker_data()


@app.get("/api/memory-save-config")
def api_memory_save_config(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _memory_save_config_data()


@app.get("/api/notify-targets")
def api_notify_targets(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked
    return _notification_targets_data()


async def _request_json_payload(request: Request) -> dict:
    try:
        payload = await request.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


@app.post("/api/memory-save-config")
async def api_update_memory_save_config(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked

    payload = await _request_json_payload(request)
    mode = payload.get("mode") if isinstance(payload.get("mode"), str) else None
    return _set_memory_save_mode(mode)


@app.post("/api/memory-save")
async def api_memory_save(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked

    payload = await _request_json_payload(request)
    reason = payload.get("reason") if isinstance(payload.get("reason"), str) else "manual"
    if reason not in {"manual", "auto_daily_23"}:
        reason = "manual"

    result = _memory_save_now(reason=reason)
    _record_memory_save_result(result, reason=reason)
    result["config"] = _memory_save_config_data()
    return result


@app.post("/api/notify-targets")
async def api_update_notify_targets(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked

    payload = await _request_json_payload(request)

    memory_target = payload.get("memory_target") if isinstance(payload.get("memory_target"), str) else None
    return _set_notification_targets(memory_target=memory_target)


@app.post("/api/notify-targets/repo")
async def api_update_repo_notify_target(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked

    payload = await _request_json_payload(request)

    repo_path = str(payload.get("repo_path") or "")
    target = payload.get("target") if isinstance(payload.get("target"), str) else None
    return _set_repo_notification_target(repo_path, target)


@app.post("/api/notify-targets/test")
async def api_test_notify_target(request: Request):
    blocked = _ensure_api_auth(request)
    if blocked:
        return blocked

    payload = await _request_json_payload(request)

    target = payload.get("target") if isinstance(payload.get("target"), str) else None
    scope = payload.get("scope") if isinstance(payload.get("scope"), str) else "manual"
    repo_name = payload.get("repo") if isinstance(payload.get("repo"), str) else ""
    branch = payload.get("branch") if isinstance(payload.get("branch"), str) else ""

    test_message = "\n".join(
        [
            "🧠 *ClawQ Testnachricht*",
            "Wenn du das liest, funktioniert die Zustellung. ✅",
            f"scope: `{scope}`",
            f"repo: `{repo_name or '-'}`",
            f"branch: `{branch or '-'}`",
            f"timestamp: `{datetime.now(timezone.utc).isoformat()}`",
        ]
    )

    effective_target = _effective_signal_target(target)
    sent, status, target_kind, error = _send_signal_message(effective_target, test_message)
    return {
        "sent": sent,
        "status": status,
        "target": _mask_target_value(effective_target),
        "target_label": _target_label_for_value(effective_target),
        "requested_target": _mask_target_value(target),
        "target_kind": target_kind,
        "error": error,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    blocked = require_auth(request)
    if blocked:
        return blocked

    readme_title, readme_html = _render_workspace_readme()
    notify_targets = _notification_targets_data()
    notify_options = notify_targets.get("options") if isinstance(notify_targets.get("options"), list) else []
    notify_memory_target = notify_targets.get("memory_target")
    notify_default_target = notify_targets.get("default_target")
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "readme_title": readme_title,
            "readme_html": readme_html,
            "notify_options": notify_options,
            "notify_memory_target": notify_memory_target,
            "notify_default_label": _target_label_for_value(notify_default_target),
            "status": _system_status(),
        },
    )
