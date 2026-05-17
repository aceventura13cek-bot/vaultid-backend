# =============================================================
# VaultID — AI Router
# File: app/routes/ai.py
# =============================================================

from fastapi import APIRouter, Depends, Request, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import select
from pydantic import BaseModel

from app.db.session import get_db
from app.models.ai_models import RiskSession
from app.core.ai_service import evaluate_login_risk, check_session_risk

router = APIRouter(prefix="/ai", tags=["AI Risk Engine"])


class LoginRiskRequest(BaseModel):
    user_id: str

class LoginRiskResponse(BaseModel):
    anomaly_score: float
    risk_level:    str
    action_taken:  str

class SessionStatusResponse(BaseModel):
    session_active: bool
    risk_level:     str


@router.post("/login-risk", response_model=LoginRiskResponse)
def login_risk(
    body:    LoginRiskRequest,
    request: Request,
    db:      Session = Depends(get_db),
):
    ip     = request.headers.get("x-forwarded-for", "").split(",")[0].strip() or request.client.host or "127.0.0.1"
    device = request.headers.get("user-agent", "unknown")

    result = evaluate_login_risk(user_id=body.user_id, ip=ip, device=device, db=db)

    if result["action_taken"] == "BLOCK":
        raise HTTPException(status_code=403, detail={
            "message": "Login blocked — suspicious activity",
            "anomaly_score": result["anomaly_score"],
            "risk_level": result["risk_level"],
        })
    return result


@router.get("/session-status/{user_id}", response_model=SessionStatusResponse)
def session_status(user_id: str, db: Session = Depends(get_db)):
    session = db.query(RiskSession).filter(RiskSession.user_id == user_id).first()
    if not session:
        return {"session_active": False, "risk_level": "UNKNOWN"}
    return {"session_active": session.is_active, "risk_level": session.current_risk}


def require_safe_session(user_id: str, db: Session = Depends(get_db)):
    check = check_session_risk(user_id, db)
    if not check["allowed"]:
        raise HTTPException(status_code=403, detail=check["reason"])
    return check
