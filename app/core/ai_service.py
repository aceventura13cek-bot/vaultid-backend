# =============================================================
# VaultID — AI Service Layer (SYNC — matches your project)
# File: app/core/ai_service.py
# =============================================================

import requests
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.ai_models import LoginLog, RiskSession

LSTM_SERVICE_URL = "http://127.0.0.1:5000/predict"
SEQUENCE_LENGTH  = 5


def lookup_geo(ip: str) -> dict:
    try:
        import geoip2.database
        reader = geoip2.database.Reader("/opt/GeoLite2-City.mmdb")
        r = reader.city(ip)
        return {
            "country": r.country.iso_code or "LOCAL",
            "region":  r.subdivisions.most_specific.iso_code or "LOCAL",
            "city":    r.city.name or "LOCAL",
        }
    except Exception:
        return {"country": "LOCAL", "region": "LOCAL", "city": "LOCAL"}


def generate_sequence(user_id: str, db: Session):
    logs = (
        db.query(LoginLog)
        .filter(LoginLog.user_id == user_id)
        .order_by(LoginLog.timestamp.asc())
        .all()
    )
    if len(logs) < SEQUENCE_LENGTH:
        return None
    features = [
        [log.time_gap, log.ip_change, log.device_change, log.location_change]
        for log in logs
    ]
    return features[-SEQUENCE_LENGTH:]


def call_lstm(sequence: list) -> dict:
    try:
        resp = requests.post(LSTM_SERVICE_URL, json={"sequence": sequence}, timeout=5)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"[AI WARNING] LSTM unreachable: {e}")
        return {"anomaly_score": 0.0}


def evaluate_login_risk(user_id: str, ip: str, device: str, db: Session) -> dict:
    now = datetime.now(timezone.utc)
    geo = lookup_geo(ip)

    last_log = (
        db.query(LoginLog)
        .filter(LoginLog.user_id == user_id)
        .order_by(desc(LoginLog.timestamp))
        .first()
    )

    time_gap = ip_change = device_change = location_change = 0
    if last_log:
        last_ts         = last_log.timestamp.replace(tzinfo=timezone.utc) if last_log.timestamp.tzinfo is None else last_log.timestamp
        time_gap        = (now - last_ts).total_seconds()
        ip_change       = 1 if last_log.ip      != ip             else 0
        device_change   = 1 if last_log.device  != device         else 0
        location_change = 1 if last_log.country != geo["country"] else 0

    anomaly_score = 0.0
    risk_level    = "LOW"
    action_taken  = "ALLOW"

    sequence = generate_sequence(user_id, db)
    if sequence:
        result        = call_lstm(sequence)
        anomaly_score = result.get("anomaly_score", 0.0)
        if   anomaly_score < 0.3: risk_level, action_taken = "LOW",    "ALLOW"
        elif anomaly_score < 0.6: risk_level, action_taken = "MEDIUM", "VERIFY"
        else:                     risk_level, action_taken = "HIGH",   "BLOCK"

    db.add(LoginLog(
        user_id=user_id, action="login", ip=ip, device=device,
        country=geo["country"], region=geo["region"], city=geo["city"],
        time_gap=time_gap, ip_change=ip_change,
        device_change=device_change, location_change=location_change,
        anomaly_score=anomaly_score, risk_level=risk_level, action_taken=action_taken,
    ))

    risk_session = db.query(RiskSession).filter(RiskSession.user_id == user_id).first()
    if risk_session:
        risk_session.current_risk = risk_level
        risk_session.last_score   = anomaly_score
        risk_session.last_updated = now
        risk_session.is_active    = (action_taken != "BLOCK")
    else:
        db.add(RiskSession(
            user_id=user_id, current_risk=risk_level,
            last_score=anomaly_score, last_updated=now,
            is_active=(action_taken != "BLOCK"),
        ))

    db.commit()
    return {"anomaly_score": anomaly_score, "risk_level": risk_level, "action_taken": action_taken}


def check_session_risk(user_id: str, db: Session) -> dict:
    session = db.query(RiskSession).filter(RiskSession.user_id == user_id).first()
    if not session:
        return {"allowed": False, "reason": "No active session", "risk_level": "UNKNOWN"}
    if not session.is_active:
        return {"allowed": False, "reason": "Session revoked", "risk_level": session.current_risk}
    if session.current_risk == "HIGH":
        session.is_active = False
        db.commit()
        return {"allowed": False, "reason": "Blocked: high risk", "risk_level": "HIGH"}
    return {"allowed": True, "reason": "OK", "risk_level": session.current_risk}
