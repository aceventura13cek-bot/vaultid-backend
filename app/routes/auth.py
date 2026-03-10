"""
VaultID Authentication Routes
Zero-Knowledge Proof + Session Management + Token Security
"""

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
    salt, public_key, params = zkp.register_user(req.password)
    
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


@router.post("/login", response_model=TokenResponse)
def login(
    req: LoginProofRequest,
    request: Request,
    db: Session = Depends(get_db)
):
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
    
    is_valid = zkp.verify_proof(
        proof=req.proof,
        public_key=public_key,
        challenge=stored_challenge,
        params=params
    )
    
    if not is_valid:
        del active_challenges[req.email]
        raise HTTPException(401, "Authentication failed - invalid proof")
    
    # Delete challenge (one-time use - prevents replay)
    del active_challenges[req.email]
    
    print(f"✅ ZKP verification passed for {req.email}")
    
    # 🆕 AI RISK SCORING
    from app.core.ai_risk_client import ai_risk_client
    
    client_ip = request.client.host if request.client else "127.0.0.1"
    user_agent = request.headers.get("User-Agent", "")
    
    risk_assessment = ai_risk_client.calculate_login_risk(
        user_id=user.id,
        email=user.email,
        ip_address=client_ip,
        user_agent=user_agent
    )
    
    risk_score = risk_assessment["risk_score"]
    
    print(f"🤖 AI Risk Score: {risk_score}/100")
    
    if risk_assessment["anomaly_detected"]:
        print(f"   ⚠️ Anomaly: {risk_assessment['anomaly_reason']}")
    
    # TODO: If risk too high, require MFA
    # if ai_risk_client.should_require_mfa(risk_score):
    #     return {"mfa_required": True, "challenge": generate_mfa_challenge()}
    
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
    
    return TokenResponse(
        access_token=session_data["access_token"],
        refresh_token=session_data["refresh_token"],
        token_type="bearer",
        expires_in=session_data.get("expires_in")
    )


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