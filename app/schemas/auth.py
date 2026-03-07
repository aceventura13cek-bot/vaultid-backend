from pydantic import BaseModel, EmailStr
from typing import Dict, Optional

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str  # ⚠️ Demo only - client computes ZKP
    dob: str

class ChallengeRequest(BaseModel):
    email: EmailStr

class ChallengeResponse(BaseModel):
    challenge: int
    expires_in: int

class LoginProofRequest(BaseModel):
    email: EmailStr
    proof: Dict
    challenge: int

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"