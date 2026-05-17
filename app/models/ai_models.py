# =============================================================
# VaultID — AI Models
# File: app/models/ai_models.py
# =============================================================

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, func
from sqlalchemy.dialects.postgresql import UUID
import uuid
from app.db.base import Base   # use YOUR existing Base


class LoginLog(Base):
    __tablename__ = "login_logs"

    id              = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id         = Column(String(255), nullable=False, index=True)
    action          = Column(String(100), nullable=False)
    ip              = Column(String(45))
    device          = Column(Text)
    country         = Column(String(10),  default="LOCAL")
    region          = Column(String(50),  default="LOCAL")
    city            = Column(String(100), default="LOCAL")
    timestamp       = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    time_gap        = Column(Float,   default=0)
    ip_change       = Column(Integer, default=0)
    device_change   = Column(Integer, default=0)
    location_change = Column(Integer, default=0)
    anomaly_score   = Column(Float,   default=0.0)
    risk_level      = Column(String(10), default="LOW")
    action_taken    = Column(String(10), default="ALLOW")


class RiskSession(Base):
    __tablename__ = "risk_sessions"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id      = Column(String(255), nullable=False, unique=True, index=True)
    current_risk = Column(String(10), default="LOW")
    last_score   = Column(Float, default=0.0)
    last_updated = Column(DateTime(timezone=True), server_default=func.now())
    is_active    = Column(Boolean, default=True)
