import asyncio
import base64
import json
import os
import secrets
import sqlite3
import subprocess
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    AuthenticatorAttestationResponse,
    AuthenticatorAssertionResponse,
    AuthenticationCredential,
    RegistrationCredential,
    ResidentKeyRequirement,
    UserVerificationRequirement,
    PublicKeyCredentialDescriptor,
)

# ── Config ────────────────────────────────────────────────────────────────────
# DASH_PASSPHRASE is only used for the one-time YubiKey registration.
# Set DASH_RP_ID to the hostname you access the dashboard from (e.g. "dash.flysqu.pink").
# Set DASH_ORIGIN to the full origin (e.g. "https://dash.flysqu.pink").
DASH_PASSPHRASE = os.environ.get("DASH_PASSPHRASE", "changeme")
RP_ID           = os.environ.get("DASH_RP_ID",      "localhost")
ORIGIN          = os.environ.get("DASH_ORIGIN",     "http://localhost:8000")

DB_PATH   = Path(__file__).parent / "uptime.db"
CRED_PATH = Path(__file__).parent / "credential.json"

TOKEN_TTL = 30 * 86400  # 30 days in seconds

app = FastAPI()

# ── Database ──────────────────────────────────────────────────────────────────

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS checks (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                service    TEXT    NOT NULL,
                checked_at REAL    NOT NULL,
                up         INTEGER NOT NULL
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_svc_time ON checks(service, checked_at)"
        )

init_db()


def store_results(results: list[dict]):
    now = time.time()
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            "INSERT INTO checks (service, checked_at, up) VALUES (?, ?, ?)",
            [(r["name"], now, 1 if r["up"] else 0) for r in results],
        )
        conn.execute("DELETE FROM checks WHERE checked_at < ?", (now - 30 * 86400,))


def get_uptime_24h(service: str) -> float | None:
    cutoff = time.time() - 86400
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT COUNT(*), SUM(up) FROM checks WHERE service = ? AND checked_at >= ?",
            (service, cutoff),
        ).fetchone()
    total, up_sum = row
    if not total:
        return None
    return round((up_sum or 0) / total * 100, 1)


def get_history(service: str, limit: int = 40) -> list[bool]:
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT up FROM checks WHERE service = ? ORDER BY checked_at DESC LIMIT ?",
            (service, limit),
        ).fetchall()
    return [bool(r[0]) for r in reversed(rows)]


# ── Credential storage ────────────────────────────────────────────────────────

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def load_credential() -> dict | None:
    if CRED_PATH.exists():
        return json.loads(CRED_PATH.read_text())
    return None


def save_credential(data: dict):
    CRED_PATH.write_text(json.dumps(data))


# ── WebAuthn challenge store ──────────────────────────────────────────────────

_pending_challenge: tuple[bytes, float] | None = None  # (bytes, expires_at)


def _store_challenge(challenge: bytes):
    global _pending_challenge
    _pending_challenge = (challenge, time.time() + 300)  # 5-minute window


def _pop_challenge() -> bytes | None:
    global _pending_challenge
    if not _pending_challenge:
        return None
    challenge, expires_at = _pending_challenge
    _pending_challenge = None
    return challenge if time.time() < expires_at else None


# ── Auth / tokens ─────────────────────────────────────────────────────────────

_tokens: dict[str, float] = {}  # token → expires_at (unix timestamp)
_bearer = HTTPBearer()


def _issue_token() -> tuple[str, float]:
    now = time.time()
    # Prune any expired tokens while we're here
    for t in [t for t, e in _tokens.items() if now > e]:
        del _tokens[t]
    token = secrets.token_urlsafe(32)
    expires = now + TOKEN_TTL
    _tokens[token] = expires
    return token, expires


def require_auth(creds: HTTPAuthorizationCredentials = Depends(_bearer)) -> str:
    token = creds.credentials
    expires = _tokens.get(token)
    if expires is None or time.time() > expires:
        _tokens.pop(token, None)
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return token


@app.post("/api/logout")
async def logout(token: str = Depends(require_auth)):
    _tokens.pop(token, None)
    return {"ok": True}


# ── WebAuthn endpoints ────────────────────────────────────────────────────────

class RegisterBeginRequest(BaseModel):
    passphrase: str


class CredentialBody(BaseModel):
    id: str
    rawId: str
    type: str
    response: dict[str, Any]


@app.get("/api/webauthn/status")
async def webauthn_status():
    return {"registered": load_credential() is not None}


@app.post("/api/webauthn/register/begin")
async def register_begin(body: RegisterBeginRequest):
    if not secrets.compare_digest(body.passphrase, DASH_PASSPHRASE):
        raise HTTPException(status_code=401, detail="Wrong passphrase")
    if load_credential() is not None:
        raise HTTPException(status_code=409, detail="Credential already registered — delete credential.json to re-register")

    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name="dashboard",
        user_id=b"dashboard-user",
        user_name="user",
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.DISCOURAGED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    _store_challenge(options.challenge)
    return json.loads(options_to_json(options))


@app.post("/api/webauthn/register/complete")
async def register_complete(body: CredentialBody):
    challenge = _pop_challenge()
    if not challenge:
        raise HTTPException(status_code=400, detail="No pending challenge")
    try:
        credential = RegistrationCredential(
            id=body.id,
            raw_id=base64url_to_bytes(body.rawId),
            response=AuthenticatorAttestationResponse(
                client_data_json=base64url_to_bytes(body.response["clientDataJSON"]),
                attestation_object=base64url_to_bytes(body.response["attestationObject"]),
            ),
        )
        verification = verify_registration_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            require_user_verification=False,
        )
    except Exception as e:
        print(f"[webauthn] registration verification failed: {e}")
        raise HTTPException(status_code=400, detail="Registration verification failed")

    save_credential({
        "id":         _b64url(verification.credential_id),
        "public_key": _b64url(verification.credential_public_key),
        "sign_count": verification.sign_count,
    })
    return {"ok": True}


@app.post("/api/webauthn/auth/begin")
async def auth_begin():
    cred = load_credential()
    if not cred:
        raise HTTPException(status_code=404, detail="No credential registered")

    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(cred["id"]))
        ],
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    _store_challenge(options.challenge)
    return json.loads(options_to_json(options))


@app.post("/api/webauthn/auth/complete")
async def auth_complete(body: CredentialBody):
    challenge = _pop_challenge()
    if not challenge:
        raise HTTPException(status_code=400, detail="No pending challenge")

    cred = load_credential()
    if not cred:
        raise HTTPException(status_code=404, detail="No credential registered")

    try:
        credential = AuthenticationCredential(
            id=body.id,
            raw_id=base64url_to_bytes(body.rawId),
            response=AuthenticatorAssertionResponse(
                client_data_json=base64url_to_bytes(body.response["clientDataJSON"]),
                authenticator_data=base64url_to_bytes(body.response["authenticatorData"]),
                signature=base64url_to_bytes(body.response["signature"]),
                user_handle=base64url_to_bytes(body.response["userHandle"])
                    if body.response.get("userHandle") else None,
            ),
        )
        verification = verify_authentication_response(
            credential=credential,
            expected_challenge=challenge,
            expected_rp_id=RP_ID,
            expected_origin=ORIGIN,
            credential_public_key=base64url_to_bytes(cred["public_key"]),
            credential_current_sign_count=cred["sign_count"],
            require_user_verification=False,
        )
    except Exception as e:
        print(f"[webauthn] authentication verification failed: {e}")
        raise HTTPException(status_code=400, detail="Authentication failed")

    cred["sign_count"] = verification.new_sign_count
    save_credential(cred)

    token, expires = _issue_token()
    return {"token": token, "expires": expires}


# ── Service definitions ───────────────────────────────────────────────────────
# Configure your services in services_config.py (gitignored).
# See services_config.example.py for the format.

from services_config import SERVICES

# ── Cache ─────────────────────────────────────────────────────────────────────

_cache: dict = {}
_cache_time: float = 0.0
CACHE_TTL = 30.0


async def _check_service(client: httpx.AsyncClient, svc: dict) -> dict:
    try:
        r = await client.get(svc.get("check_url", svc["url"]))
        up = r.status_code < 500
    except Exception:
        up = False
    return {**svc, "up": up}


def _check_vpn() -> bool:
    result = subprocess.run(
        ["ping", "-c", "2", "-W", "2", "10.8.0.1"],
        capture_output=True,
    )
    return result.returncode == 0


@app.get("/api/status")
async def status(_token: str = Depends(require_auth)):
    global _cache, _cache_time

    if _cache and (time.time() - _cache_time) < CACHE_TTL:
        return _cache

    loop = asyncio.get_event_loop()
    async with httpx.AsyncClient(verify=False, timeout=5.0) as client:
        svc_results, vpn_up = await asyncio.gather(
            asyncio.gather(*[_check_service(client, svc) for svc in SERVICES]),
            loop.run_in_executor(None, _check_vpn),
        )
    results = list(svc_results)

    store_results(results)
    for svc in results:
        svc["uptime_24h"] = get_uptime_24h(svc["name"])
        svc["history"]    = get_history(svc["name"])

    _cache = {"vpn": vpn_up, "services": results}
    _cache_time = time.time()
    return _cache


# ── Block backend directory from static serving ───────────────────────────────
# StaticFiles serves ~/dashboard/ which includes the backend/ subdirectory.
# This route intercepts any /backend/* request before it reaches StaticFiles.

@app.get("/backend/{path:path}")
async def block_backend(path: str):
    raise HTTPException(status_code=404)


# ── Static files (must be last) ───────────────────────────────────────────────

_static_dir = str(Path(__file__).parent.parent)
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
