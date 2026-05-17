"""
VaultID OAuth 2.0 Authorization Server
"""

import secrets
import time
from fastapi import APIRouter, Depends, HTTPException, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.db.session import get_db
from app.models.user import User

router = APIRouter(prefix="/oauth", tags=["oauth"])

OAUTH_CLIENTS = {
    "thinked_client": {
        "client_id":     "thinked_client",
        "client_secret": "thinked_secret_2026",
        "redirect_uris": [
            "http://localhost:5500/callback.html",
            "http://127.0.0.1:5500/callback.html",
            "http://127.0.0.1:5500",
            "http://localhost:5500",
        ],
        "app_name":    "thinkED Academy",
        "app_logo":    "📚",
        "app_desc":    "Online learning platform",
        "allowed_scopes": ["profile", "email", "openid"],
    }
}

pending_auth: dict = {}
auth_codes:   dict = {}


class AuthRequest:
    def __init__(self, client_id, redirect_uri, scope, state, user_email=None):
        self.client_id    = client_id
        self.redirect_uri = redirect_uri
        self.scope        = scope
        self.state        = state
        self.user_email   = user_email
        self.created_at   = time.time()


SCOPE_DESCRIPTIONS = {
    "profile": "Read your name and profile information",
    "email":   "Read your email address",
    "openid":  "Verify your identity",
}


def render_consent_page(client: dict, scopes: list, state: str, user_email: str) -> str:
    scope_items = "\n".join(
        f'<li><span class="scope-icon">✓</span>{SCOPE_DESCRIPTIONS.get(s, s)}</li>'
        for s in scopes
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>VaultID — Authorize {client['app_name']}</title>
<link href="https://fonts.googleapis.com/css2?family=Pacifico&display=swap" rel="stylesheet"/>
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#050d08;--panel:#0a100d;--neon:#4ED378;--neon-dim:rgba(78,211,120,0.15);
  --text:#d4e8db;--muted:#5a8068;--white:#e8f5ed;--error:#f87171;
  --border:rgba(78,211,120,0.2);--font:'Helvetica Neue',Arial,sans-serif;
}}
body{{background:var(--bg);font-family:var(--font);color:var(--text);
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}}
.card{{
  background:var(--panel);border:1px solid var(--border);border-radius:20px;
  padding:40px;width:min(480px,100%);
  box-shadow:0 20px 60px rgba(0,0,0,0.6),0 0 80px rgba(78,211,120,0.06);
  animation:cardIn 0.5s cubic-bezier(0.16,1,0.3,1) both;
}}
@keyframes cardIn{{from{{opacity:0;transform:translateY(20px)}}to{{opacity:1;transform:translateY(0)}}}}
.logo-name{{font-family:'Pacifico',cursive;font-size:26px;color:#fff;margin-bottom:24px;}}
.app-block{{
  display:flex;align-items:center;gap:14px;
  background:rgba(78,211,120,0.05);border:1px solid var(--border);
  border-radius:12px;padding:16px;margin-bottom:24px;
}}
.app-emoji{{font-size:32px;}}
.app-name{{font-weight:700;font-size:16px;color:var(--white);}}
.app-desc{{font-size:12px;color:var(--muted);margin-top:2px;}}
.request-line{{font-size:13px;color:var(--muted);margin-bottom:20px;}}
.request-line strong{{color:var(--white);}}
.user-badge{{
  display:inline-flex;align-items:center;gap:6px;
  background:rgba(78,211,120,0.08);border:1px solid var(--border);
  border-radius:20px;padding:4px 12px;font-size:12px;font-weight:600;
  color:var(--neon);margin-bottom:20px;
}}
.perms{{background:rgba(0,0,0,0.2);border-radius:10px;padding:16px;margin-bottom:24px;}}
.perms h5{{font-size:11px;letter-spacing:0.1em;text-transform:uppercase;color:var(--muted);margin-bottom:12px;}}
.perms ul{{list-style:none;display:flex;flex-direction:column;gap:8px;}}
.perms li{{font-size:13px;color:var(--text);display:flex;align-items:center;gap:8px;}}
.scope-icon{{color:var(--neon);font-weight:700;}}
.buttons{{display:flex;gap:12px;margin-bottom:16px;}}
.btn-allow{{
  flex:1;padding:13px;background:var(--neon);color:#000;border:none;
  border-radius:10px;font-weight:700;font-size:13px;letter-spacing:0.06em;
  text-transform:uppercase;cursor:pointer;
  transition:background 0.2s,box-shadow 0.2s,transform 0.1s;
  box-shadow:0 0 20px rgba(78,211,120,0.3);
}}
.btn-allow:hover{{background:#62e888;box-shadow:0 0 30px rgba(78,211,120,0.5);transform:translateY(-1px);}}
.btn-deny{{
  flex:1;padding:13px;background:transparent;color:var(--muted);
  border:1.5px solid rgba(255,255,255,0.1);border-radius:10px;
  font-weight:700;font-size:13px;letter-spacing:0.06em;text-transform:uppercase;
  cursor:pointer;transition:border-color 0.2s,color 0.2s;
}}
.btn-deny:hover{{border-color:var(--error);color:var(--error);}}
.note{{font-size:11px;color:var(--muted);text-align:center;line-height:1.5;}}
.note strong{{color:var(--white);}}
</style>
</head>
<body>
<div class="card">
  <div class="logo-name">VaultID</div>

  <div class="app-block">
    <div class="app-emoji">{client['app_logo']}</div>
    <div>
      <div class="app-name">{client['app_name']}</div>
      <div class="app-desc">{client['app_desc']}</div>
    </div>
  </div>

  <p class="request-line"><strong>{client['app_name']}</strong> wants to access your VaultID account</p>

  <div class="user-badge">
    🔐 Signed in as {user_email}
  </div>

  <div class="perms">
    <h5>Requested permissions</h5>
    <ul>{scope_items}</ul>
  </div>

  <div class="buttons">
    <form action="/oauth/approve" method="post" style="flex:1">
      <input type="hidden" name="state" value="{state}"/>
      <input type="hidden" name="user_email" value="{user_email}"/>
      <button class="btn-allow" type="submit">Allow Access</button>
    </form>
    <form action="/oauth/deny" method="post" style="flex:1">
      <input type="hidden" name="state" value="{state}"/>
      <button class="btn-deny" type="submit">Deny</button>
    </form>
  </div>

  <p class="note">
    Only allow access if you trust <strong>{client['app_name']}</strong>.<br/>
    You can revoke access anytime from your VaultID dashboard.
  </p>
</div>
</body>
</html>"""


def render_login_required_page(authorize_url: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>VaultID — Login Required</title>
<link href="https://fonts.googleapis.com/css2?family=Pacifico&display=swap" rel="stylesheet"/>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#050d08;font-family:'Helvetica Neue',Arial,sans-serif;color:#d4e8db;
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;}}
.card{{background:#0a100d;border:1px solid rgba(78,211,120,0.2);border-radius:20px;
  padding:40px;width:min(420px,100%);text-align:center;
  box-shadow:0 20px 60px rgba(0,0,0,0.6);}}
.logo{{font-family:'Pacifico',cursive;font-size:28px;color:#fff;margin-bottom:16px;}}
p{{color:#5a8068;font-size:13px;margin-bottom:24px;line-height:1.6;}}
.btn{{display:block;padding:14px;background:#4ED378;color:#000;border-radius:10px;
  font-weight:700;font-size:13px;letter-spacing:0.08em;text-transform:uppercase;
  text-decoration:none;transition:background 0.2s;}}
.btn:hover{{background:#62e888;}}
</style>
</head>
<body>
<div class="card">
  <div class="logo">VaultID</div>
  <p>You need to sign in to VaultID before authorizing this application.</p>
  <a class="btn" href="/login.html?next={authorize_url}">Sign In with VaultID →</a>
</div>
</body>
</html>"""


@router.get("/authorize", response_class=HTMLResponse)
def oauth_authorize(
    request: Request,
    client_id: str,
    redirect_uri: str,
    scope: str = "profile email",
    state: str = "",
    response_type: str = "code",
    login_hint: str = "",
    db: Session = Depends(get_db)
):
    client = OAUTH_CLIENTS.get(client_id)
    if not client:
        raise HTTPException(400, f"Unknown client_id: '{client_id}'")

    if redirect_uri not in client["redirect_uris"]:
        raise HTTPException(400, f"Invalid redirect_uri for client '{client_id}'")

    requested_scopes = [s.strip() for s in scope.split()]
    invalid_scopes = [s for s in requested_scopes if s not in client["allowed_scopes"]]
    if invalid_scopes:
        raise HTTPException(400, f"Invalid scopes: {invalid_scopes}")

    # Try to get user email from Authorization header
    user_email = None

# Try Authorization header first (API calls)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            token = auth_header.split(" ")[1]
            from app.core.tokens import verify_access_token
            payload = verify_access_token(token)
            if payload:
              user_email = payload.get("sub")
        except Exception:
           pass

# Fallback: read token from query param (sent by thinkED frontend)
   # Fallback: read from browser cookie (set at VaultID login)
    if not user_email:
        cookie_token = request.cookies.get("vaultid_session")
        if cookie_token:
            try:
                from app.core.tokens import verify_access_token
                payload = verify_access_token(cookie_token)
                if payload:
                    user_email = payload.get("sub")
                    print(f"[DEBUG] Got email from cookie: {user_email}")
            except Exception as e:
                print(f"[DEBUG] Cookie error: {e}")

    if not state:
        state = secrets.token_urlsafe(16)

    pending_auth[state] = AuthRequest(
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=requested_scopes,
        state=state,
        user_email=user_email
    )

    # Look up real name from DB for consent page display
    display_name = user_email or "your account"
    if user_email and user_email != "your account":
        try:
            from app.models.user import User
            db_user = db.query(User).filter(User.email == user_email).first()
            if db_user and db_user.name:
                display_name = db_user.name
        except Exception:
            pass
    return render_consent_page(client, requested_scopes, state, display_name)


@router.post("/approve")
def oauth_approve(
    state: str = Form(...),
    user_email: str = Form(None),
    db: Session = Depends(get_db)
):
    req = pending_auth.get(state)
    if not req:
        raise HTTPException(400, "Invalid or expired authorization request")
    if time.time() - req.created_at > 600:
        del pending_auth[state]
        raise HTTPException(400, "Authorization request expired. Please try again.")

    # Get real name from DB using email
    real_email = user_email or req.user_email or ""
    real_name  = None

    if real_email and real_email != "your account":
        db_user = db.query(User).filter(User.email == real_email).first()
        if db_user:
            real_name  = db_user.name
            real_email = db_user.email

    if not real_name:
        real_name = real_email.split("@")[0] if real_email else "Learner"

    code = secrets.token_urlsafe(32)
    auth_codes[code] = {
        "client_id":    req.client_id,
        "redirect_uri": req.redirect_uri,
        "scope":        req.scope,
        "created_at":   time.time(),
        "used":         False,
        "user_name":    real_name,
        "user_email":   real_email,
    }
    del pending_auth[state]
    redirect_url = f"{req.redirect_uri}?code={code}&state={state}"
    print(f"✅ OAuth approved: {req.client_id} → {real_name} ({real_email}) → {req.redirect_uri}")
    return RedirectResponse(redirect_url, status_code=302)


@router.post("/deny")
def oauth_deny(state: str = Form(...)):
    auth_req = pending_auth.get(state)
    if auth_req:
        redirect_url = f"{auth_req.redirect_uri}?error=access_denied&state={state}"
        del pending_auth[state]
        print(f"❌ OAuth denied for {auth_req.client_id}")
        return RedirectResponse(redirect_url, status_code=302)
    raise HTTPException(400, "Invalid state")


class TokenRequest(BaseModel):
    grant_type:    str
    code:          str
    redirect_uri:  str
    client_id:     str
    client_secret: str

issued_tokens: dict = {}
@router.post("/token")
def oauth_token(req: TokenRequest, db: Session = Depends(get_db)):
    if req.grant_type != "authorization_code":
        raise HTTPException(400, "Only authorization_code grant type supported")

    client = OAUTH_CLIENTS.get(req.client_id)
    if not client or client["client_secret"] != req.client_secret:
        raise HTTPException(401, "Invalid client credentials")

    code_data = auth_codes.get(req.code)
    if not code_data:
        raise HTTPException(400, "Invalid authorization code")

    if code_data["used"]:
        raise HTTPException(400, "Authorization code already used")

    if time.time() - code_data["created_at"] > 300:
        del auth_codes[req.code]
        raise HTTPException(400, "Authorization code expired")

    if code_data["client_id"] != req.client_id:
        raise HTTPException(400, "Code was not issued to this client")

    if code_data["redirect_uri"] != req.redirect_uri:
        raise HTTPException(400, "redirect_uri mismatch")

    auth_codes[req.code]["used"] = True

    # Configurable expiry — default 15 min
    expires_in   = code_data.get("expires_in", 900)  # 900s = 15 min
    access_token = secrets.token_urlsafe(32)
    issued_at    = time.time()
    user_name    = code_data.get("user_name",  "Learner")
    user_email   = code_data.get("user_email", "")

    # Store issued token for validation
    issued_tokens[access_token] = {
        "client_id":  req.client_id,
        "user_email": user_email,
        "user_name":  user_name,
        "issued_at":  issued_at,
        "expires_at": issued_at + expires_in,
        "expires_in": expires_in,
    }

    print(f"🎫 OAuth token issued for {req.client_id} → {user_name} ({user_email}) expires in {expires_in//60}min")

    return {
        "access_token": access_token,
        "token_type":   "bearer",
        "expires_in":   expires_in,
        "issued_at":    int(issued_at),
        "scope":        " ".join(code_data["scope"]),
        "user": {
            "name":  user_name,
            "email": user_email,
        }
    }
@router.get("/token/status")
def token_status(token: str, db: Session = Depends(get_db)):
    """Check if OAuth token is valid and get remaining time"""
    data = issued_tokens.get(token)
    if not data:
        return {"valid": False, "reason": "Token not found or revoked"}
    remaining = data["expires_at"] - time.time()
    if remaining <= 0:
        del issued_tokens[token]
        return {"valid": False, "reason": "Token expired"}
    return {
        "valid":      True,
        "client_id":  data["client_id"],
        "user_name":  data["user_name"],
        "user_email": data["user_email"],
        "expires_in": int(remaining),
        "issued_at":  int(data["issued_at"]),
        "expires_at": int(data["expires_at"]),
    }

@router.post("/token/revoke")
def revoke_token(token: str, db: Session = Depends(get_db)):
    """Revoke an OAuth token"""
    if token in issued_tokens:
        del issued_tokens[token]
        return {"revoked": True}
    return {"revoked": False, "reason": "Token not found"}

@router.get("/clients/{client_id}")
def get_client_info(client_id: str):
    client = OAUTH_CLIENTS.get(client_id)
    if not client:
        raise HTTPException(404, "Client not found")
    return {
        "client_id": client["client_id"],
        "app_name":  client["app_name"],
        "app_logo":  client["app_logo"],
        "app_desc":  client["app_desc"],
        "scopes":    client["allowed_scopes"],
    }
