"""
VaultID Authentication Routes
Zero-Knowledge Proof + Session Management + Token Security
"""

from unittest import result
from urllib import request

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import datetime, date, timezone

from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import (
    RegisterRequest,
    ChallengeRequest,
    ChallengeResponse,
    LoginProofRequest,
    TokenResponse,
    RefreshRequest
)
from app.core.zkp import zkp
from app.core.session_manager import session_manager
from app.core.tokens import verify_refresh_token, hash_token_jti
from app.core.deps import get_current_user
from app.schemas.auth import MFALoginRequest  
router = APIRouter(prefix="/auth", tags=["auth"])

# Challenge storage (use Redis in production)
active_challenges = {}


@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    """
    Register new user with Zero-Knowledge Proof
    
    ⚠️ DEMO MODE: Server generates ZKP parameters
    ✅ PRODUCTION: Client sends pre-computed public key
    """
    # Check if user exists
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Email already registered")
    
    # Generate ZKP parameters (CLIENT-SIDE in production!)
    result = zkp.register_user(req.password)
    salt       = result['salt']
    public_key = result['public_key']
    params     = result['params']
    
    # Create user with ZKP (NO PASSWORD!)
    user = User(
        name=req.name,
        email=req.email,
        dob=date.fromisoformat(req.dob),
        zkp_public_key=str(public_key),
        zkp_salt=salt,
        zkp_params=params
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    print(f"✅ User registered: {req.email}")
    print(f"   🔐 ZKP Public Key stored (password NEVER stored!)")
    
    return {
        "message": "User registered successfully",
        "email": req.email,
        "user_id": user.id
    }


@router.post("/challenge", response_model=ChallengeResponse)
def get_challenge(req: ChallengeRequest, db: Session = Depends(get_db)):
    """
    Step 1 of ZKP Login: Generate Challenge
    """
    # Verify user exists
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(404, "User not found")
    
    # Generate random challenge
    challenge = zkp.generate_challenge()
    
    # Store challenge temporarily (5 min expiry)
    active_challenges[req.email] = challenge
    
    print(f"🔑 Challenge generated for {req.email}")
    
    return ChallengeResponse(
        challenge=str(challenge),
        expires_in=300
    )
from app.schemas.auth import ZKPParamsResponse

@router.get("/zkp-params", response_model=ZKPParamsResponse)
def get_zkp_params(email: str, db: Session = Depends(get_db)):
    """
    Get user's ZKP parameters for proof generation
    
    PUBLIC endpoint - no auth required (user needs params to generate proof)
    Salt and params are NOT sensitive (public-key cryptography)
    """
    user = db.query(User).filter(User.email == email).first()
    
    if not user:
        raise HTTPException(404, "User not found")
    
    return ZKPParamsResponse(
        salt=user.zkp_salt,
        params=user.zkp_params  # {p, q, g}
    )

@router.post("/login", response_model=TokenResponse)
def login(
    req: LoginProofRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    print(f"📥 req.proof type: {type(req.proof)}")
    print(f"📥 req.proof: {req.proof}")
    print(f"📥 req.proof keys: {list(req.proof.keys()) if isinstance(req.proof, dict) else 'NOT A DICT'}")
    """
    Step 2 of ZKP Login: Verify Proof + Create Session
    
    NEW FEATURES:
    - Creates secure session with device binding
    - Issues hashed tokens (not stored raw!)
    - Tracks device and location
    - AI risk scoring
    """
    # Get user
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(401, "Invalid credentials")
    
    # Verify challenge exists
    if req.email not in active_challenges:
        raise HTTPException(400, "Challenge expired. Request new challenge.")
    
    stored_challenge = active_challenges[req.email]
    
    # ✅ VERIFY ZERO-KNOWLEDGE PROOF
    public_key = int(user.zkp_public_key)
    params = user.zkp_params
    print(f"🔍 proof keys received: {list(req.proof.keys())}")
    print(f"🔍 proof value: {str(req.proof)[:200]}")
    stored_challenge = active_challenges[req.email]

# Cast ALL values to int
    # Support both old format and new Schnorr ZKP format
    if "commitment" in req.proof and "response" in req.proof:
        proof_parsed = {
            "commitment": int(req.proof["commitment"]),
            "response":   int(req.proof["response"])
        }
    else:
        print(f"❌ Wrong proof format received: {list(req.proof.keys())}")
        raise HTTPException(400, f"Invalid proof format. Expected commitment+response, got: {list(req.proof.keys())}")
    params_parsed = {
    "p": int(user.zkp_params["p"]),
    "q": int(user.zkp_params["q"]),
    "g": int(user.zkp_params["g"])
    }
    is_valid = zkp.verify_proof(
    proof=proof_parsed,
    public_key=public_key,
    challenge=stored_challenge,
    params=params_parsed
    )
    
    if not is_valid:
        del active_challenges[req.email]
        raise HTTPException(401, "Authentication failed - invalid proof")
    
    # Delete challenge (one-time use - prevents replay)
    del active_challenges[req.email]
    
    print(f"✅ ZKP verification passed for {req.email}")
    
    # 🤖 AI RISK SCORING (LSTM)
# 🤖 AI RISK SCORING (LSTM)
    from app.core.ai_service import evaluate_login_risk
    client_ip  = request.headers.get("x-forwarded-for", "").split(",")[0].strip() \
             or (request.client.host if request.client else "127.0.0.1")
    user_agent = request.headers.get("User-Agent", "unknown")

    ai_result    = evaluate_login_risk(str(user.id), client_ip, user_agent, db)
    risk_score   = int(ai_result["anomaly_score"] * 100)
    action_taken = ai_result["action_taken"]

    print(f"🤖 AI Risk: {risk_score}/100 → {action_taken}")

    if action_taken == "BLOCK":
      raise HTTPException(403, f"Login blocked: suspicious activity (score {risk_score}/100)")
 
    if action_taken == "VERIFY":
        return {
        "access_token":  None,
        "refresh_token": None,
        "token_type":    "bearer",
        "expires_in":    None,
        "mfa_required":  True,
        "risk_level":    ai_result["risk_level"],
        "email":         user.email,
        "name":          user.name,
    }
    
    # 🆕 CREATE SESSION WITH RISK SCORE
    session_data = session_manager.create_session(
        db=db,
        user=user,
        request=request,
        risk_score=risk_score
    )
    
    # Update user last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()
    
    print(f"🎫 Session created: {session_data['session_id'][:20]}...")
    print(f"   Device: {user_agent[:50]}...")
    print(f"   IP: {client_ip}")
    print(f"   Risk: {risk_score}/100")
    
    from fastapi.responses import JSONResponse
    response = JSONResponse(content={
        "access_token":  session_data["access_token"],
        "refresh_token": session_data["refresh_token"],
        "token_type":    "bearer",
        "expires_in":    session_data.get("expires_in"),
        "name":          user.name,
        "email":         user.email,
    })
    response.set_cookie(
        key="vaultid_session",
        value=session_data["access_token"],
        httponly=False,
        samesite="lax",
        max_age=900,
        path="/",
    )
    return response


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(
    req: RefreshRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Refresh Access Token with Rotation
    
    🔐 SECURITY FEATURES:
    - One-time use refresh tokens
    - Automatic rotation on every use
    - Replay attack detection
    - Breach response (revoke all sessions)
    
    Process:
    1. Verify refresh token
    2. Check if already used (replay detection)
    3. Issue NEW access + refresh tokens
    4. Blacklist old refresh token
    5. Return new tokens
    """
    from app.core.token_rotation import token_rotation_manager
    
    return token_rotation_manager.rotate_refresh_token(
        refresh_token=req.refresh_token,
        request=request,
        db=db
    )


@router.get("/me")
def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get Current User Info
    
    Protected route - requires valid access token
    """
    return {
        "id": current_user.id,
        "name": current_user.name,
        "email": current_user.email,
        "dob": str(current_user.dob),
        "zkp_enabled": True,
        "last_login": str(current_user.last_login) if current_user.last_login else None
    }


@router.post("/logout")
def logout(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout - Revoke current session
    
    Request body:
    {
        "session_id": "session_xyz..."
    }
    """
    revoked = session_manager.revoke_session(db, session_id, "user_logout")
    
    if revoked:
        return {"message": "Logged out successfully"}
    else:
        raise HTTPException(404, "Session not found")


@router.get("/sessions")
def list_sessions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all active sessions for current user
    
    Returns list of sessions with device info, location, last activity
    """
    sessions = session_manager.get_active_sessions(db, current_user.id)
    
    return {
        "sessions": [
            {
                "session_id": s.session_id,
                "device_name": s.device_name,
                "location": s.location,
                "ip_address": str(s.ip_address) if s.ip_address else None,
                "created_at": str(s.created_at),
                "last_activity": str(s.last_activity),
                "risk_score": s.risk_score,
                "is_current": False  # TODO: Detect current session from token
            }
            for s in sessions
        ],
        "total": len(sessions)
    }


@router.post("/sessions/{session_id}/revoke")
def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revoke a specific session by ID
    
    Use case: "Log out from my iPhone"
    """
    # Verify session belongs to current user
    from app.models.session import Session as SessionModel
    
    session = db.query(SessionModel).filter(
        SessionModel.session_id == session_id,
        SessionModel.user_id == current_user.id
    ).first()
    
    if not session:
        raise HTTPException(404, "Session not found or doesn't belong to you")
    
    revoked = session_manager.revoke_session(db, session_id, "user_revoke")
    
    if revoked:
        return {
            "message": "Session revoked successfully",
            "session_id": session_id
        }
    else:
        raise HTTPException(400, "Failed to revoke session")


@router.post("/logout-all")
def logout_all_devices(
    current_session_id: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout from all devices (revoke all sessions)
    
    Optional: Keep current session active by passing current_session_id
    
    Request body:
    {
        "current_session_id": "session_xyz..." (optional)
    }
    """
    count = session_manager.revoke_all_sessions(
        db,
        current_user.id,
        except_session_id=current_session_id
    )
    
    return {
        "message": f"Logged out from {count} device(s)",
        "sessions_revoked": count
    }
@router.get("/ai/health")
def check_ai_service():
    """
    Check if AI risk service is available
    """
    from app.core.ai_risk_client import ai_risk_client
    
    is_healthy = ai_risk_client.check_health()
    
    return {
        "ai_service_available": is_healthy,
        "ai_service_url": ai_risk_client.ai_service_url,
        "status": "healthy" if is_healthy else "unavailable"
    }
# MFA ENDPOINTS

@router.post("/mfa/setup")
def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Setup MFA for user
    
    Returns QR code and backup codes
    """
    from app.core.mfa import mfa_manager
    
    if current_user.mfa_enabled:
        raise HTTPException(400, "MFA already enabled")
    
    # Generate TOTP secret
    secret = mfa_manager.generate_totp_secret()
    
    # Generate QR code
    qr_code = mfa_manager.generate_qr_code(current_user.email, secret)
    
    # Generate backup codes
    backup_codes = mfa_manager.generate_backup_codes()
    hashed_codes = [mfa_manager.hash_backup_code(code) for code in backup_codes]
    
    # Save to user (not enabled yet - requires verification)
    current_user.totp_secret = secret
    current_user.backup_codes = hashed_codes
    db.commit()
    
    print(f"🔐 MFA setup initiated for {current_user.email}")
    
    return {
        "qr_code": qr_code,
        "secret": secret,
        "backup_codes": backup_codes,
        "message": "Scan QR code with authenticator app, then verify to enable MFA"
    }


@router.post("/mfa/verify")
def verify_mfa_setup(
    code: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Verify and enable MFA
    
    User must verify TOTP code to activate MFA
    """
    from app.core.mfa import mfa_manager
    
    if current_user.mfa_enabled:
        raise HTTPException(400, "MFA already enabled")
    
    if not current_user.totp_secret:
        raise HTTPException(400, "MFA not setup. Call /mfa/setup first")
    
    # Verify code
    is_valid = mfa_manager.verify_totp(current_user.totp_secret, code)
    
    if not is_valid:
        raise HTTPException(401, "Invalid MFA code")
    
    # Enable MFA
    current_user.mfa_enabled = True
    current_user.mfa_verified_at = datetime.now(timezone.utc)
    db.commit()
    
    print(f"✅ MFA enabled for {current_user.email}")
    
    return {
        "message": "MFA enabled successfully",
        "mfa_enabled": True
    }


@router.post("/mfa/disable")
def disable_mfa(
    code: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Disable MFA (requires valid code)
    """
    from app.core.mfa import mfa_manager
    
    if not current_user.mfa_enabled:
        raise HTTPException(400, "MFA not enabled")
    
    # Verify code or backup code
    is_valid = (
        mfa_manager.verify_totp(current_user.totp_secret, code) or
        mfa_manager.verify_backup_code(code, current_user.backup_codes)
    )
    
    if not is_valid:
        raise HTTPException(401, "Invalid MFA code")
    
    # Disable MFA
    current_user.mfa_enabled = False
    current_user.totp_secret = None
    current_user.backup_codes = None
    db.commit()
    
    print(f"⚠️ MFA disabled for {current_user.email}")
    
    return {"message": "MFA disabled"}


@router.get("/mfa/status")
def mfa_status(current_user: User = Depends(get_current_user)):
    """
    Check if MFA is enabled for user
    """
    return {
        "mfa_enabled": current_user.mfa_enabled,
        "mfa_verified_at": str(current_user.mfa_verified_at) if current_user.mfa_verified_at else None
    }
@router.post("/mfa-login", response_model=TokenResponse)
def mfa_login(
    req: MFALoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(401, "Invalid credentials")

    from app.core.mfa import mfa_manager

    totp_valid = False
    if user.totp_secret:
        totp_valid = mfa_manager.verify_totp(user.totp_secret, req.code)

    backup_valid = False
    if not totp_valid and user.backup_codes:
        backup_valid = mfa_manager.verify_backup_code(req.code, user.backup_codes)
        if backup_valid:
            code_hash = mfa_manager.hash_backup_code(req.code)
            user.backup_codes = [c for c in user.backup_codes if c != code_hash]
            db.commit()

    if not totp_valid and not backup_valid:
        raise HTTPException(401, "Invalid MFA code")

    session_data = session_manager.create_session(
        db=db, user=user, request=request, risk_score=30
    )
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    return {
        "access_token":  session_data["access_token"],
        "refresh_token": session_data["refresh_token"],
        "token_type":    "bearer",
        "expires_in":    session_data.get("expires_in"),
        "name":          user.name,
        "email":         user.email,
    }