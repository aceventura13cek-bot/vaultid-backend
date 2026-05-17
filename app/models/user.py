from sqlalchemy import Column, Integer, String, Date, Text, TIMESTAMP, Boolean
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime, timezone
from app.db.base import Base

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    dob = Column(Date, nullable=False)
    
    # ZKP Fields
    zkp_public_key = Column(Text, nullable=False)
    zkp_salt = Column(String, nullable=False)
    zkp_params = Column(JSONB, nullable=False)
    
    # Timestamps
    created_at = Column(TIMESTAMP(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_login = Column(TIMESTAMP(timezone=True), nullable=True)
    
    # Security
    last_password_change = Column(TIMESTAMP(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(TIMESTAMP(timezone=True), nullable=True)
    security_alerts_enabled = Column(Boolean, default=True)
    
    # MFA (NEW)
    mfa_enabled = Column(Boolean, default=False)
    totp_secret = Column(Text, nullable=True)
    backup_codes = Column(JSONB, nullable=True)
    mfa_verified_at = Column(TIMESTAMP(timezone=True), nullable=True)