from pydantic import BaseModel, EmailStr
from typing import Dict, Optional

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    dob: str

class ChallengeRequest(BaseModel):
    email: EmailStr

class ChallengeResponse(BaseModel):
    challenge: str  # Changed from int to str
    expires_in: int

class LoginProofRequest(BaseModel):
    email: EmailStr
    proof: Dict
    challenge: int

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: Optional[int] = None  # ✅ Add this line

class RefreshRequest(BaseModel):
    refresh_token: str