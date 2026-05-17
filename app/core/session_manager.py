"""
Session Management for VaultID
Handles session creation, tracking, and revocation
"""

import secrets
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Dict
from sqlalchemy.orm import Session
from fastapi import Request

from app.models.session import Session as SessionModel, TokenBlacklist, TokenUsageLog
from app.models.user import User
from app.core.tokens import (
    hash_token_jti,
    hash_ip_address,
    generate_device_fingerprint,
    parse_device_info,
    create_hashed_access_token,
    create_hashed_refresh_token
)
from app.config import settings


class SessionManager:
    """
    Manages user sessions with device binding and location tracking
    """
    
    @staticmethod
    def create_session(
        db: Session,
        user: User,
        request: Request,
        risk_score: int = 0
    ) -> Dict:
        """
        Create new session and issue tokens
        
        Returns: {
            'access_token': str,
            'refresh_token': str,
            'session_id': str,
            'expires_in': int
        }
        """
        # Generate unique session ID
        session_id = secrets.token_urlsafe(32)
        
        # Extract request metadata
        user_agent = request.headers.get("User-Agent", "")
        accept_language = request.headers.get("Accept-Language", "")
        client_ip = request.client.host if request.client else "127.0.0.1"
        
        # Device fingerprinting
        device_fingerprint = generate_device_fingerprint(user_agent, accept_language)
        device_info = parse_device_info(user_agent)
        
        # Hash IP for privacy
        ip_hash = hash_ip_address(client_ip)
        
        # Create tokens
        access_token, access_jti_hash = create_hashed_access_token(
            user_id=user.id,
            email=user.email,
            session_id=session_id,
            device_fingerprint=device_fingerprint,
            ip_hash=ip_hash,
            risk_score=risk_score
        )
        
        refresh_token, refresh_jti_hash = create_hashed_refresh_token(
            user_id=user.id,
            email=user.email,
            session_id=session_id
        )
        
        # Calculate expiry
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        
        # Create session record
        session = SessionModel(
            user_id=user.id,
            session_id=session_id,
            device_fingerprint=device_fingerprint,
            device_name=device_info["device_name"],
            user_agent=user_agent,
            ip_address=client_ip,
            ip_hash=ip_hash,
            location="Unknown",  # TODO: Add geolocation
            refresh_token_hash=refresh_jti_hash,
            current_access_token_jti_hash=access_jti_hash,
            expires_at=expires_at,
            risk_score=risk_score
        )
        
        db.add(session)
        
        # Log token issuance
        SessionManager._log_token_action(
            db=db,
            user_id=user.id,
            session_id=session_id,
            jti_hash=access_jti_hash,
            action="issued",
            token_type="access",
            ip_address=client_ip,
            user_agent=user_agent,
            risk_score=risk_score
        )
        
        db.commit()
        
        print(f"✅ Session created: {session_id[:20]}... for user {user.email}")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "session_id": session_id,
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # seconds
        }
    
    @staticmethod
    def get_active_sessions(db: Session, user_id: int) -> List[SessionModel]:
        """
        Get all active sessions for a user
        """
        return db.query(SessionModel).filter(
            SessionModel.user_id == user_id,
            SessionModel.is_active == True,
            SessionModel.expires_at > datetime.now(timezone.utc)
        ).all()
    
    @staticmethod
    def revoke_session(db: Session, session_id: str, reason: str = "user_logout"):
        """
        Revoke a specific session
        """
        session = db.query(SessionModel).filter(
            SessionModel.session_id == session_id
        ).first()
        
        if not session:
            return False
        
        # Mark session as inactive
        session.is_active = False
        
        # Blacklist refresh token (check for duplicate first)
        if session.refresh_token_hash:
            existing = db.query(TokenBlacklist).filter(
                TokenBlacklist.jti_hash == session.refresh_token_hash
            ).first()
            if not existing:
                blacklist = TokenBlacklist(
                    jti_hash=session.refresh_token_hash,
                    user_id=session.user_id,
                    token_type="refresh",
                    reason=reason,
                    expires_at=session.expires_at
                )
                db.add(blacklist)
        
        # Log revocation
        SessionManager._log_token_action(
            db=db,
            user_id=session.user_id,
            session_id=session_id,
            jti_hash=session.refresh_token_hash,
            action="revoked",
            token_type="refresh"
        )
        
        db.commit()
        
        print(f"✅ Session revoked: {session_id[:20]}...")
        return True
    
    @staticmethod
    def revoke_all_sessions(db: Session, user_id: int, except_session_id: str = None):
        """
        Revoke all user sessions (e.g., "Log out all devices")
        """
        sessions = SessionManager.get_active_sessions(db, user_id)
        
        count = 0
        for session in sessions:
            if session.session_id != except_session_id:
                SessionManager.revoke_session(db, session.session_id, "revoke_all")
                count += 1
        
        print(f"✅ Revoked {count} sessions for user {user_id}")
        return count
    
    @staticmethod
    def is_token_blacklisted(db: Session, jti_hash: str) -> bool:
        """
        Check if token is blacklisted
        """
        blacklisted = db.query(TokenBlacklist).filter(
            TokenBlacklist.jti_hash == jti_hash,
            TokenBlacklist.expires_at > datetime.now(timezone.utc)
        ).first()
        
        return blacklisted is not None
    
    @staticmethod
    def update_session_activity(db: Session, session_id: str, new_access_jti_hash: str = None):
        """
        Update last activity timestamp
        """
        session = db.query(SessionModel).filter(
            SessionModel.session_id == session_id
        ).first()
        
        if session:
            session.last_activity = datetime.now(timezone.utc)
            
            if new_access_jti_hash:
                session.current_access_token_jti_hash = new_access_jti_hash
            
            db.commit()
    
    @staticmethod
    def cleanup_expired_tokens(db: Session) -> int:
        """
        Clean up expired blacklisted tokens
        
        Should be called periodically (cron job or background task)
        
        Returns: Number of tokens cleaned up
        """
        result = db.query(TokenBlacklist).filter(
            TokenBlacklist.expires_at < datetime.now(timezone.utc)
        ).delete()
        
        db.commit()
        
        print(f"🧹 Cleaned up {result} expired tokens from blacklist")
        return result
    
    @staticmethod
    def _log_token_action(
        db: Session,
        user_id: int,
        session_id: str,
        jti_hash: str,
        action: str,
        token_type: str = "access",
        ip_address: str = None,
        user_agent: str = None,
        risk_score: int = 0,
        anomaly_detected: bool = False,
        anomaly_reason: str = None
    ):
        """
        Log token usage for audit trail
        """
        log = TokenUsageLog(
            user_id=user_id,
            session_id=session_id,
            jti_hash=jti_hash,
            action=action,
            token_type=token_type,
            ip_address=ip_address,
            user_agent=user_agent,
            risk_score=risk_score,
            anomaly_detected=anomaly_detected,
            anomaly_reason=anomaly_reason
        )
        
        db.add(log)
        # Don't commit here - let caller handle transaction


# Convenience instance
session_manager = SessionManager()