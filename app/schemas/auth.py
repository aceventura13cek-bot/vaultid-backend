from pydantic import BaseModel, EmailStr, field_validator

class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    dob: str


class ChallengeRequest(BaseModel):
    email: EmailStr


class ChallengeResponse(BaseModel):
    challenge: str
    expires_in: int


from typing import Dict  # ← Import Dict


class LoginProofRequest(BaseModel):
    """
    ZKP Login Request
    
    Proof format (Schnorr):
    {
        "commitment": "big_number_as_string",  # t = g^r mod p
        "response": "big_number_as_string"     # s = (r - c*secret) mod q
    }
    """
    email: EmailStr
    proof: Dict[str, str]  # ← Fixed: typed dict instead of untyped dict
    challenge: str | int

    @field_validator('challenge', mode='before')
    @classmethod
    def parse_challenge(cls, v):
        """Convert challenge to int"""
        if isinstance(v, str):
            return int(v.strip())
        return int(v)
    
    @field_validator('proof')
    @classmethod
    def validate_proof_format(cls, v):
        """Ensure proof has correct Schnorr format"""
        required_keys = {'commitment', 'response'}
        if not isinstance(v, dict):
            raise ValueError('Proof must be a dictionary')
        
        provided_keys = set(v.keys())
        if provided_keys != required_keys:
            raise ValueError(
                f'Invalid proof format. Expected keys: {required_keys}, '
                f'got: {provided_keys}'
            )
        
        return v

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int | None = None
    name: str | None = None
    email: str | None = None

class RefreshRequest(BaseModel):
    refresh_token: str


class MFASetupRequest(BaseModel):
    """Request to setup MFA"""
    pass


class MFASetupResponse(BaseModel):
    """Response with QR code and backup codes"""
    qr_code: str
    secret: str
    backup_codes: list[str]


class MFAVerifyRequest(BaseModel):
    """Verify MFA code"""
    code: str


class MFADisableRequest(BaseModel):
    """Disable MFA"""
    code: str

class ZKPParamsResponse(BaseModel):
    """User's ZKP parameters for proof generation"""
    salt: str
    params: Dict[str, str]  # {p, q, g} as strings

class MFALoginRequest(BaseModel):
    email: str
    code: str

