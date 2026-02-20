# ClawQ

Simple password-protected ClawQ web GUI.

## Run

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
CLAWQ_PASSWORD="your-password" uvicorn app.main:app --host 0.0.0.0 --port 8080
```

`CLAWQ_PASSWORD` is required. Open `http://localhost:8080` and log in with that value.

Optional hardening for HTTPS deployments:

```bash
CLAWQ_COOKIE_SECURE=true
CLAWQ_COOKIE_SECRET="long-random-secret"
```

Optional repository root override:

```bash
CLAWQ_REPOS_ROOT="/root/git"
# README in Memory defaults to /root/workspaces/README.md
# Optional override:
# CLAWQ_README_PATH="/root/workspaces/README.md"
```

## Hooker Notifications

Hooker notifications are always active.

- `Repo Hooker` watches all discovered repos and detects new commits by `HEAD` changes.
- `Memory Hooker` watches the repository that contains the Memory README (`/root/workspaces/README.md` by default).
- Scan interval is 5 seconds.
- Notifications are delivered through OpenClaw (`openclaw message send --channel signal ...`).

Target routing:

- Default target is the OpenClaw primary Signal contact (`channels.signal.allowFrom[0]`, fallback `channels.signal.account`).
- Repo Hooker supports per-repo overrides in the table dropdown (`Default` means main contact).
- Memory Hooker has its own dropdown target.
- Group options in dropdowns include readable group names (derived from OpenClaw session metadata) plus a short group id.

Test buttons:

- `Test` sends a real Signal test notification to the currently selected target.
- If a target is empty/invalid in UI state, the backend falls back to the default main contact.

Auth cookie is long-lived (20 years) and effectively permanent unless password/secret changes or logout clears it.

## Routes

- `/` dashboard (auth required)
- `/api/status` JSON status (auth required)
- `/api/repo-hooker` repo commit watcher snapshot (auth required)
- `/api/memory-hooker` memory repo commit watcher snapshot (auth required)
- `/api/notify-targets` get/update Signal notification targets (auth required)
- `/api/notify-targets/repo` update per-repo target override (auth required)
- `/api/notify-targets/test` send test notification to selected target (auth required)
- `/health` basic liveness
- `/login` login form

## systemd Autostart

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

sudo cp deployment/systemd/clawq-webgui.service /etc/systemd/system/clawq-webgui.service
sudo cp deployment/systemd/clawq-webgui.env.example /etc/default/clawq-webgui
sudo nano /etc/default/clawq-webgui

sudo systemctl daemon-reload
sudo systemctl enable --now clawq-webgui
sudo systemctl status clawq-webgui
```
