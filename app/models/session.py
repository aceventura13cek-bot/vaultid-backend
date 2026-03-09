"""
Session and Token Security Models
"""
from sqlalchemy import Column, Integer, String, Boolean, TIMESTAMP, ForeignKey, Text
from sqlalchemy.dialects.postgresql import INET
from datetime import datetime, timezone

from app.db.base import Base


class Session(Base):
    """
    Active user sessions with device and location binding
    """
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(String(64), unique=True, nullable=False, index=True)
    
    # Device Information
    device_fingerprint = Column(String(255))
    device_name = Column(String(100))
    user_agent = Column(Text)
    
    # Location Information
    ip_address = Column(INET)
    ip_hash = Column(String(64))
    location = Column(String(100))
    
    # Token Hashes
    refresh_token_hash = Column(String(64), unique=True, index=True)
    current_access_token_jti_hash = Column(String(64))
    
    # Session Metadata
    created_at = Column(TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    last_activity = Column(TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(TIMESTAMP, nullable=False)
    is_active = Column(Boolean, default=True)
    
    # Security
    risk_score = Column(Integer, default=0)
    mfa_verified = Column(Boolean, default=False)


class TokenBlacklist(Base):
    """
    Revoked token hashes (blacklist)
    """
    __tablename__ = "token_blacklist"
    
    id = Column(Integer, primary_key=True, index=True)
    jti_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    token_type = Column(String(20), nullable=False)
    revoked_at = Column(TIMESTAMP, default=lambda: datetime.now(timezone.utc))
    reason = Column(String(50))
    expires_at = Column(TIMESTAMP, nullable=False)


class TokenUsageLog(Base):
    """
    Audit log for token operations
    """
    __tablename__ = "token_usage_log"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    session_id = Column(String(64))
    jti_hash = Column(String(64))
    
    # Action details
    action = Column(String(50), nullable=False)
    token_type = Column(String(20))
    
    # Request metadata
    ip_address = Column(INET)
    user_agent = Column(Text)
    endpoint = Column(String(100))
    
    # Security
    risk_score = Column(Integer, default=0)
    anomaly_detected = Column(Boolean, default=False)
    anomaly_reason = Column(Text)
    
    # Timestamp
    timestamp = Column(TIMESTAMP, default=lambda: datetime.now(timezone.utc))