from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from datetime import datetime, date
from jose import jwt

from app.db.session import get_db
from app.models.user import User
from app.schemas.auth import *
from app.core.zkp import zkp
from app.core.security import create_access_token, create_refresh_token
from app.core.deps import get_current_user
from app.config import settings

router = APIRouter(prefix="/auth", tags=["auth"])

# Challenge storage (use Redis in production)
active_challenges = {}

@router.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == req.email).first():
        raise HTTPException(400, "Email exists")
    
    salt, public_key, params = zkp.register_user(req.password)
    
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
    
    return {"message": "Registered", "email": req.email}

@router.post("/challenge")
def get_challenge(req: ChallengeRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(404, "User not found")
    
    challenge = zkp.generate_challenge()
    
    # Store FULL challenge (don't truncate!)
    active_challenges[req.email] = challenge
    
    # Return challenge as string to avoid JSON int overflow
    return {"challenge": str(challenge), "expires_in": 300}
@router.post("/login")
def login(req: LoginProofRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == req.email).first()
    if not user:
        raise HTTPException(401, "Invalid")
    
    if req.email not in active_challenges:
        raise HTTPException(400, "Get challenge first")
    
    stored_challenge = active_challenges[req.email]
    
    # DEBUG LOGGING
    print("\n🔍 DEBUG - Login Verification:")
    print(f"   User email: {req.email}")
    print(f"   Challenge sent: {req.challenge}")
    print(f"   Challenge stored: {stored_challenge}")
    print(f"   Challenges match: {req.challenge == stored_challenge}")
    print(f"   Public key (first 50): {user.zkp_public_key[:50]}...")
    print(f"   Proof commitment (first 50): {req.proof['commitment'][:50]}...")
    print(f"   Proof response (first 50): {req.proof['response'][:50]}...")
    
    # Verify proof
    is_valid = zkp.verify_proof(
        req.proof,
        int(user.zkp_public_key),
        stored_challenge,  # Use STORED challenge, not request challenge
        user.zkp_params
    )
    
    print(f"   Verification result: {is_valid}")
    
    if not is_valid:
        del active_challenges[req.email]
        raise HTTPException(401, "Invalid proof")
    
    del active_challenges[req.email]
    
    user.last_login = datetime.utcnow()
    db.commit()
    
    return TokenResponse(
        access_token=create_access_token({"sub": user.email}),
        refresh_token=create_refresh_token({"sub": user.email})
    )
@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "name": user.name, "email": user.email}