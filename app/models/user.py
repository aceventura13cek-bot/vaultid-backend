from sqlalchemy import Column, Integer, String, Date, Text, TIMESTAMP
from sqlalchemy.dialects.postgresql import JSONB
from datetime import datetime
from app.db.base import Base

class User(Base):
    """
    User Model - ZERO-KNOWLEDGE PROOF
    
    ❌ NO password field
    ✅ ONLY ZKP public key
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    dob = Column(Date, nullable=False)
    
    # ✅ ZKP Fields (NO PASSWORD!)
    zkp_public_key = Column(Text, nullable=False)
    zkp_salt = Column(String, nullable=False)
    zkp_params = Column(JSONB, nullable=False)
    
    # Timestamps
    created_at = Column(TIMESTAMP, default=datetime.utcnow)
    last_login = Column(TIMESTAMP, nullable=True)