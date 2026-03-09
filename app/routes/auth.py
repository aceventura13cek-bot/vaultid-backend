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
    - Risk scoring ready
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
        
        # TODO: Increment failed login attempts
        # user.failed_login_attempts += 1
        # db.commit()
        
        raise HTTPException(401, "Authentication failed - invalid proof")
    
    # Delete challenge (one-time use - prevents replay)
    del active_challenges[req.email]
    
    print(f"✅ ZKP verification passed for {req.email}")
    
    # 🆕 CREATE SESSION WITH TOKENS
    # TODO: Get risk score from AI service (default 0 for now)
    risk_score = 0  # Will integrate AI engineer's work here
    
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
    print(f"   Device: {request.headers.get('User-Agent', 'Unknown')[:50]}...")
    print(f"   IP: {request.client.host if request.client else 'Unknown'}")
    
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
    Refresh Access Token
    
    NEW: Implements token rotation (one-time use refresh tokens)
    """
    try:
        # Verify refresh token
        payload = verify_refresh_token(req.refresh_token)
        
        email = payload.get("sub")
        session_id = payload.get("session_id")
        jti = payload.get("jti")
        
        if not email or not session_id or not jti:
            raise HTTPException(401, "Invalid refresh token")
        
        # Hash the JTI
        jti_hash = hash_token_jti(jti)
        
        # Check if token is blacklisted
        if session_manager.is_token_blacklisted(db, jti_hash):
            raise HTTPException(401, "Refresh token has been revoked")
        
        # Get user
        user = db.query(User).filter(User.email == email).first()
        if not user:
            raise HTTPException(401, "User not found")
        
        # 🔄 TOKEN ROTATION (Coming in Step 5)
        # For now, just issue new access token
        from app.core.tokens import create_hashed_access_token, hash_ip_address
        
        client_ip = request.client.host if request.client else "127.0.0.1"
        ip_hash = hash_ip_address(client_ip)
        
        access_token, access_jti_hash = create_hashed_access_token(
            user_id=user.id,
            email=user.email,
            session_id=session_id,
            ip_hash=ip_hash,
            risk_score=0
        )
        
        # Update session activity
        session_manager.update_session_activity(db, session_id, access_jti_hash)
        
        print(f"🔄 Token refreshed for {email}")
        
        # TODO: Implement full rotation in Step 5
        return TokenResponse(
            access_token=access_token,
            refresh_token=req.refresh_token,  # Same for now
            token_type="bearer"
        )
    
    except Exception as e:
        raise HTTPException(401, f"Invalid refresh token: {str(e)}")


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
                "is_current": False  # TODO: Detect current session
            }
            for s in sessions
        ],
        "total": len(sessions)
    }


@router.post("/logout-all")
def logout_all_devices(
    current_session_id: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Logout from all devices (revoke all sessions)
    """
    count = session_manager.revoke_all_sessions(
        db,
        current_user.id,
        except_session_id=current_session_id
    )
    
    return {
        "message": f"Logged out from {count} devices",
        "sessions_revoked": count
    }