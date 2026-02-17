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

Auth cookie is long-lived (20 years) and effectively permanent unless password/secret changes or logout clears it.

## Routes

- `/` dashboard (auth required)
- `/api/status` JSON status (auth required)
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
