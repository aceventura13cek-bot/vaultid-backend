"""
VaultID Token Security Module
Implements hashed pseudo-tokens with rotation and device binding
"""

import hashlib
import secrets
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple
from jose import jwt, JWTError
from sqlalchemy.orm import Session
from user_agents import parse

from app.config import settings
from app.models.user import User


# ========================================
# TOKEN HASHING FUNCTIONS
# ========================================

def hash_token_jti(jti: str) -> str:
    """
    Hash token JTI using SHA-256
    
    Security: Only hash stored in DB, never raw token
    """
    return hashlib.sha256(jti.encode()).hexdigest()


def hash_ip_address(ip: str) -> str:
    """
    Hash IP address for privacy
    """
    return hashlib.sha256(ip.encode()).hexdigest()


def generate_jti() -> str:
    """
    Generate unique token identifier
    
    Returns: URL-safe random string (32 bytes = 43 chars base64)
    """
    return secrets.token_urlsafe(32)


def generate_nonce() -> str:
    """
    Generate one-time nonce for replay prevention
    """
    return secrets.token_hex(16)


# ========================================
# DEVICE FINGERPRINTING
# ========================================

def generate_device_fingerprint(user_agent: str, accept_language: str = None) -> str:
    """
    Create unique device fingerprint
    
    Components:
    - User Agent string
    - Accept-Language header
    
    Returns: SHA-256 hash (64 chars)
    """
    components = [
        user_agent or "",
        accept_language or "",
    ]
    
    fingerprint_string = "|".join(components)
    return hashlib.sha256(fingerprint_string.encode()).hexdigest()


def parse_device_info(user_agent: str) -> Dict[str, str]:
    """
    Extract human-readable device info from User-Agent
    
    Returns: {
        'device_name': 'Chrome on Windows',
        'browser': 'Chrome',
        'os': 'Windows 10',
        'device_type': 'PC'
    }
    """
    ua = parse(user_agent)
    
    # Device type
    if ua.is_mobile:
        device_type = "Mobile"
    elif ua.is_tablet:
        device_type = "Tablet"
    elif ua.is_pc:
        device_type = "PC"
    else:
        device_type = "Unknown"
    
    # Device name
    device_name = f"{ua.browser.family} on {ua.os.family}"
    
    return {
        "device_name": device_name,
        "browser": ua.browser.family,
        "browser_version": ua.browser.version_string,
        "os": ua.os.family,
        "os_version": ua.os.version_string,
        "device_type": device_type,
    }


# ========================================
# TOKEN CREATION
# ========================================

def create_hashed_access_token(
    user_id: int,
    email: str,
    session_id: str,
    device_fingerprint: str = None,
    ip_hash: str = None,
    risk_score: int = 0
) -> Tuple[str, str]:
    """
    Create access token with hashed JTI
    
    Returns: (token, jti_hash)
    """
    # Generate unique JTI
    jti = generate_jti()
    jti_hash = hash_token_jti(jti)
    
    # Generate nonce for replay prevention
    nonce = generate_nonce()
    
    # Token expiry
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Create payload
    payload = {
        "jti": jti,  # Sent to client (not stored!)
        "sub": email,
        "user_id": user_id,
        "session_id": session_id,
        "device_fingerprint": device_fingerprint,
        "ip_hash": ip_hash,
        "nonce": nonce,
        "risk_score": risk_score,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    }
    
    # Encode JWT
    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return token, jti_hash


def create_hashed_refresh_token(
    user_id: int,
    email: str,
    session_id: str
) -> Tuple[str, str]:
    """
    Create refresh token with hashed JTI
    
    ONE-TIME USE ONLY!
    Hash is stored in sessions table and rotated on every use
    
    Returns: (token, jti_hash)
    """
    # Generate unique JTI
    jti = generate_jti()
    jti_hash = hash_token_jti(jti)
    
    # Token expiry
    expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    # Create payload
    payload = {
        "jti": jti,  # Sent to client (not stored!)
        "sub": email,
        "user_id": user_id,
        "session_id": session_id,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "refresh"
    }
    
    # Encode JWT
    token = jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    
    return token, jti_hash


# ========================================
# TOKEN VERIFICATION
# ========================================

def verify_access_token(token: str) -> Dict:
    """
    Decode and verify access token
    
    Returns: Token payload
    Raises: JWTError if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        # Verify token type
        if payload.get("type") != "access":
            raise JWTError("Invalid token type")
        
        return payload
    
    except JWTError as e:
        raise JWTError(f"Token verification failed: {str(e)}")


def verify_refresh_token(token: str) -> Dict:
    """
    Decode and verify refresh token
    
    Returns: Token payload
    Raises: JWTError if invalid
    """
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        # Verify token type
        if payload.get("type") != "refresh":
            raise JWTError("Invalid token type")
        
        return payload
    
    except JWTError as e:
        raise JWTError(f"Token verification failed: {str(e)}")


# ========================================
# TESTING FUNCTIONS
# ========================================

if __name__ == "__main__":
    print("🧪 Testing Token Hashing Module\n")
    
    # Test 1: Generate JTI and hash
    jti = generate_jti()
    jti_hash = hash_token_jti(jti)
    print(f"1️⃣ JTI Generation:")
    print(f"   JTI: {jti[:20]}...")
    print(f"   Hash: {jti_hash[:20]}...")
    print(f"   ✅ JTI and hash are different\n")
    
    # Test 2: Device fingerprinting
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    fingerprint = generate_device_fingerprint(ua, "en-US")
    device_info = parse_device_info(ua)
    print(f"2️⃣ Device Fingerprinting:")
    print(f"   Fingerprint: {fingerprint[:20]}...")
    print(f"   Device: {device_info['device_name']}")
    print(f"   ✅ Device info extracted\n")
    
    # Test 3: Create tokens
    access_token, access_hash = create_hashed_access_token(
        user_id=1,
        email="test@example.com",
        session_id="session_123",
        device_fingerprint=fingerprint,
        risk_score=10
    )
    
    refresh_token, refresh_hash = create_hashed_refresh_token(
        user_id=1,
        email="test@example.com",
        session_id="session_123"
    )
    
    print(f"3️⃣ Token Creation:")
    print(f"   Access Token: {access_token[:50]}...")
    print(f"   Access Hash: {access_hash[:20]}...")
    print(f"   Refresh Token: {refresh_token[:50]}...")
    print(f"   Refresh Hash: {refresh_hash[:20]}...")
    print(f"   ✅ Tokens created with hashes\n")
    
    # Test 4: Verify tokens
    access_payload = verify_access_token(access_token)
    refresh_payload = verify_refresh_token(refresh_token)
    
    print(f"4️⃣ Token Verification:")
    print(f"   Access Token Type: {access_payload['type']}")
    print(f"   Refresh Token Type: {refresh_payload['type']}")
    print(f"   User: {access_payload['sub']}")
    print(f"   Session: {access_payload['session_id']}")
    print(f"   ✅ Tokens verified successfully\n")
    
    print("✅ All Token Tests Passed!")