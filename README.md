# dashboard :3

A personal home server dashboard with real-time service uptime monitoring, WebAuthn (YubiKey) authentication, and WireGuard VPN status.

![dashboard screenshot](https://i.postimg.cc/4N8GCDGS/Screenshot-20260219-002433.png)

## Features

- **YubiKey authentication** - WebAuthn/FIDO2, no passwords. 30-day persistent sessions with a re-auth button and days-remaining indicator.
- **Service health checks** - concurrent async HTTP checks for all services, with live status dots.
- **Uptime tracking** - SQLite-backed 24h uptime percentage and 40-entry history bar per service, retained for 30 days.
- **VPN status** - pings the WireGuard peer to show tunnel connectivity.
- **Dark/light theme** - persisted in localStorage.
- **Responsive** - works on mobile.

## Stack

- **Backend** - [FastAPI](https://fastapi.tiangolo.com/) + [uvicorn](https://www.uvicorn.org/), served as a single process
- **Auth** - [py_webauthn](https://github.com/duo-labs/py_webauthn) for WebAuthn registration and authentication
- **HTTP checks** - [httpx](https://www.python-httpx.org/) async client, all services checked concurrently
- **Storage** - SQLite for uptime history, `credential.json` for the WebAuthn credential
- **Frontend** - vanilla JS, no framework. [Bootstrap Icons](https://icons.getbootstrap.com/) for service icons.
- **Font** - [Coiny](https://fonts.google.com/specimen/Coiny) from Google Fonts

## Setup

### Requirements

- Python 3.11+
- A YubiKey (or any FIDO2 authenticator)

### Running locally

```bash
git clone https://github.com/flysqu/dashboard
cd dashboard/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

DASH_PASSPHRASE=yourpassphrase \
DASH_RP_ID=localhost \
DASH_ORIGIN=http://localhost:8000 \
uvicorn main:app --port 8000
```

Open `http://localhost:8000`. On first launch you'll be prompted to register your YubiKey using the setup passphrase.

### Configuration

All config is via environment variables:

| Variable | Default | Description |
|---|---|---|
| `DASH_PASSPHRASE` | `changeme` | One-time passphrase used only for initial YubiKey registration |
| `DASH_RP_ID` | `localhost` | WebAuthn relying party ID — must match the hostname you access the dashboard from |
| `DASH_ORIGIN` | `http://localhost:8000` | Full origin URL (e.g. `https://dash.example.com`) |

### Deploying

The backend serves the frontend as static files via FastAPI's `StaticFiles`. A single uvicorn process handles everything. Point a reverse proxy (nginx) at it and set the environment variables above.

For production, run as a systemd service:

```ini
[Service]
WorkingDirectory=/opt/dashboard/backend
ExecStart=/opt/dashboard/backend/venv/bin/uvicorn main:app --host 0.0.0.0 --port 8000
Environment=DASH_PASSPHRASE=...
Environment=DASH_RP_ID=dash.example.com
Environment=DASH_ORIGIN=https://dash.example.com
Restart=on-failure
```

### Customising services

Copy `backend/services_config.example.py` to `backend/services_config.py` and edit it (it's gitignored so your personal config stays local):

```python
SERVICES = [
    {"name": "website",   "icon": "bi-globe2",               "desc": "personal site", "url": "https://flysqu.pink",           "tag": "public"},
    {"name": "nextcloud", "icon": "bi-cloud-fill",           "desc": "files & sync",  "url": "https://cloud.flysqu.pink",     "tag": "public"},
    {"name": "jellyfin",  "icon": "bi-collection-play-fill", "desc": "media server",  "url": "https://media.flysqu.pink",     "tag": "public"},
    {"name": "bitwarden", "icon": "bi-shield-lock-fill",     "desc": "passwords",     "url": "https://bitwarden.flysqu.pink", "tag": "public"},
    # VPN-only: check_url uses the internal LAN IP for health checks,
    # url is what you open in your browser when on the VPN.
    {"name": "proxmox",   "icon": "bi-server",               "desc": "hypervisor",    "url": "https://10.8.0.2:8006",         "tag": "vpn",
     "check_url": "https://192.168.1.1:8006"},
]
```

`tag` is either `"public"` or `"vpn"` — controls which section the card appears in. `check_url` lets the backend use a different URL for health checks than the one shown on the card (useful when the dashboard runs inside your LAN but links should point to WireGuard IPs).

## Security notes

- The setup passphrase is only used once, at YubiKey registration time. Once registered, delete it from your environment or rotate it — it's never used again.
- Re-registration is blocked if a credential already exists. To register a new key, delete `backend/credential.json` and restart.
- Tokens are in-memory and invalidated on restart. Sessions last 30 days.
