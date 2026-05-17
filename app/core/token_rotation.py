"""
Refresh Token Rotation System
ONE-TIME USE TOKENS - Maximum Security
"""

from datetime import datetime, timezone
from sqlalchemy.orm import Session
from fastapi import HTTPException, Request

from app.models.user import User
from app.models.session import Session as SessionModel, TokenBlacklist
from app.core.tokens import (
    verify_refresh_token,
    hash_token_jti,
    create_hashed_access_token,
    create_hashed_refresh_token,
    hash_ip_address
)
from app.core.session_manager import session_manager


class TokenRotationManager:
    """
    Handles secure refresh token rotation
    
    Security Features:
    1. One-time use refresh tokens
    2. Automatic rotation on every refresh
    3. Replay attack detection
    4. Breach detection and response
    """
    
    @staticmethod
    def rotate_refresh_token(
        refresh_token: str,
        request: Request,
        db: Session
    ) -> dict:
        """
        Rotate refresh token and issue new access + refresh tokens
        
        Process:
        1. Verify refresh token
        2. Find session by refresh token hash
        3. Check if already used (replay attack detection)
        4. Issue NEW access + refresh tokens
        5. Update session with NEW refresh token hash
        6. Blacklist OLD refresh token
        7. Return new tokens
        
        Returns: {
            'access_token': str,
            'refresh_token': str,
            'token_type': 'bearer'
        }
        """
        # Step 1: Verify refresh token signature
        try:
            payload = verify_refresh_token(refresh_token)
        except Exception as e:
            raise HTTPException(401, f"Invalid refresh token: {str(e)}")
        
        # Extract payload
        email = payload.get("sub")
        session_id = payload.get("session_id")
        jti = payload.get("jti")
        user_id = payload.get("user_id")
        
        if not all([email, session_id, jti, user_id]):
            raise HTTPException(401, "Invalid refresh token payload")
        
        # Step 2: Hash the JTI
        jti_hash = hash_token_jti(jti)
        
        # Step 3: CRITICAL - Check if token already used (REPLAY ATTACK!)
        if session_manager.is_token_blacklisted(db, jti_hash):
            print(f"🚨 SECURITY ALERT: Refresh token reuse detected!")
            print(f"   User: {email}")
            print(f"   Session: {session_id}")
            print(f"   Action: Revoking ALL user sessions")
            
            # BREACH DETECTED - Revoke ALL sessions
            TokenRotationManager._handle_token_reuse_breach(
                db=db,
                user_id=user_id,
                session_id=session_id,
                jti_hash=jti_hash
            )
            
            raise HTTPException(
                401,
                "Security breach detected: Refresh token was already used. All sessions revoked."
            )
        
        # Step 4: Find session by refresh token hash
        session = db.query(SessionModel).filter(
            SessionModel.refresh_token_hash == jti_hash,
            SessionModel.is_active == True
        ).first()
        
        if not session:
            raise HTTPException(401, "Session not found or expired")
        
        # Step 5: Verify session hasn't expired
        now = datetime.now(timezone.utc)
        session_expires = session.expires_at.replace(tzinfo=timezone.utc) if session.expires_at.tzinfo is None else session.expires_at

        if session.expires_at.tzinfo is None:
            session_expires = session.expires_at.replace(tzinfo=timezone.utc)
        else:
            session_expires = session.expires_at

        if session_expires < now:
            session.is_active = False
            db.commit()
            raise HTTPException(401, "Session expired")
        
        # Step 6: Get user
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(401, "User not found")
        
        # Step 7: Generate NEW tokens
        client_ip = request.client.host if request.client else "127.0.0.1"
        ip_hash = hash_ip_address(client_ip)
        
        # Create NEW access token
        new_access_token, new_access_jti_hash = create_hashed_access_token(
            user_id=user.id,
            email=user.email,
            session_id=session_id,
            device_fingerprint=session.device_fingerprint,
            ip_hash=ip_hash,
            risk_score=session.risk_score
        )
        
        # Create NEW refresh token
        new_refresh_token, new_refresh_jti_hash = create_hashed_refresh_token(
            user_id=user.id,
            email=user.email,
            session_id=session_id
        )
        
        # Step 8: Update session with NEW refresh token hash
        old_refresh_hash = session.refresh_token_hash
        session.refresh_token_hash = new_refresh_jti_hash
        session.current_access_token_jti_hash = new_access_jti_hash
        session.last_activity = datetime.now(timezone.utc)
        
        # Step 9: Blacklist OLD refresh token (immediate invalidation)
        old_token_blacklist = TokenBlacklist(
            jti_hash=old_refresh_hash,
            user_id=user.id,
            token_type="refresh",
            reason="token_rotation",
            expires_at=session.expires_at
        )
        db.add(old_token_blacklist)
        
        # Step 10: Log rotation
        from app.models.session import TokenUsageLog
        
        log = TokenUsageLog(
            user_id=user.id,
            session_id=session_id,
            jti_hash=new_refresh_jti_hash,
            action="refreshed",
            token_type="refresh",
            ip_address=client_ip,
            user_agent=request.headers.get("User-Agent", ""),
            risk_score=session.risk_score
        )
        db.add(log)
        
        db.commit()
        
        print(f"🔄 Token rotated for {email}")
        print(f"   Session: {session_id[:20]}...")
        print(f"   Old refresh token: BLACKLISTED ✅")
        print(f"   New tokens: ISSUED ✅")
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer",
            "expires_in": 900  # 15 minutes in seconds
        }
    
    @staticmethod
    def _handle_token_reuse_breach(
        db: Session,
        user_id: int,
        session_id: str,
        jti_hash: str
    ):
        """
        Handle security breach when refresh token is reused
        
        Actions:
        1. Revoke ALL user sessions
        2. Log security incident
        3. Send alert to user (TODO)
        4. Flag account for review (TODO)
        """
        # Revoke all sessions
        sessions_revoked = session_manager.revoke_all_sessions(db, user_id)
        
        # Log security incident
        from app.models.session import TokenUsageLog
        
        incident_log = TokenUsageLog(
            user_id=user_id,
            session_id=session_id,
            jti_hash=jti_hash,
            action="rejected",
            token_type="refresh",
            risk_score=100,  # Maximum risk
            anomaly_detected=True,
            anomaly_reason="Refresh token reuse detected - possible token theft"
        )
        db.add(incident_log)
        db.commit()
        
        print(f"🚨 SECURITY BREACH HANDLED:")
        print(f"   User ID: {user_id}")
        print(f"   Sessions revoked: {sessions_revoked}")
        print(f"   Incident logged: YES")
        
        # TODO: Send email alert to user
        # TODO: Require password reset
        # TODO: Notify security team


# Singleton instance
token_rotation_manager = TokenRotationManager()