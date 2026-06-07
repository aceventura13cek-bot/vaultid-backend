# VaultID — Zero-Knowledge Authentication with AI

> "Passwords Are Dead. Here's What Replaced Them."

VaultID is a next-generation identity provider that eliminates 
password storage using Zero-Knowledge Proofs and integrates 
real-time AI-driven risk detection using LSTM neural networks.

## What Makes It Different

| Feature | Traditional OAuth 2.0 | VaultID |
|---|---|---|
| Password stored | Hashed in DB | Never stored |
| Credential transmitted | Yes | No (ZKP) |
| Anomaly detection | None | LSTM real-time |
| Token type | Static bearer | Device-bound rotating |
| Adaptive MFA | Manual | Auto on risk score |
| Replay prevention | Optional | Mandatory + blacklist |

## Architecture
Browser (ZKP Proof Generator)
↓ HTTPS
FastAPI Backend (port 8000)
├── ZKP Verifier (Schnorr Protocol)
├── Token Manager (JWT + Rotation)
├── Session Manager
├── OAuth 2.0 Server
└── AI Integration Layer
↓ HTTP
LSTM Flask Microservice (port 5000)
↓ SQL
PostgreSQL Database
ThinkED Academy (port 5500) — Demo third-party app

## Key Results
- ✅ 99.67% LSTM anomaly detection accuracy
- ✅ 187ms average total login latency
- ✅ 0 passwords stored in database
- ✅ 0 passwords transmitted over network
- ✅ Sub-40ms AI inference latency
- ✅ Full OAuth 2.0 Authorization Code Flow

## How ZKP Login Works

1. User enters password — stays in browser
2. Browser derives secret x using PBKDF2 (260,000 iterations)
3. Browser computes commitment C = g^r mod p
4. Server returns random challenge e
5. Browser computes response s = (r + e·x) mod q
6. Server verifies: g^s mod p == C · V^e mod p
7. Password never leaves the device

## Tech Stack

- **Backend:** Python 3.12, FastAPI, Uvicorn
- **Database:** PostgreSQL 16, SQLAlchemy ORM
- **AI/ML:** TensorFlow 2.x, Keras, LSTM, Flask
- **Cryptography:** Schnorr ZKP, PBKDF2-HMAC-SHA256
- **Auth:** OAuth 2.0, JWT, TOTP (RFC 6238)
- **Frontend:** Vanilla HTML/CSS/JavaScript, Web Crypto API

## Running the Project

```bash
# Terminal 1 — Backend + Frontend
cd vaultid-backend && source venv/bin/activate
uvicorn app.main:app --port 8000 --reload

# Terminal 2 — LSTM Microservice
cd vaultid-backend/ML_model && python lstm_inference.py

# Terminal 3 — ThinkED Demo App
cd vaultid-backend/vaultid-frontend && python3 -m http.server 5500
```

## Demo Flow

1. Register at http://127.0.0.1:8000/register.html
2. Login — ZKP proof generated in browser
3. Enable MFA on dashboard
4. Next login requires TOTP code
5. Connect thinkED at http://localhost:5500
6. OAuth consent flow with real username
7. Revoke access from VaultID dashboard

## Project Structure
vaultid-backend/
├── app/
│   ├── core/          # ZKP, tokens, MFA, AI service, session
│   ├── models/        # SQLAlchemy ORM models
│   ├── routes/        # FastAPI routers
│   ├── schemas/       # Pydantic models
│   └── db/            # Database setup
├── ML_model/          # LSTM training and inference
├── frontend/          # VaultID HTML pages
└── vaultid-frontend/  # ThinkED demo application

## Published / Recognized
- Final year B.Tech project — College of Engineering Kallooppara
- Recommended for publication by project guide
- External examiner appreciation

## Team
- Adhil Shamsudeen — Token Engineer
- Alex John — ZKP Engineer & Backend
- Nivitha Lucy Abraham — OAuth Architect & MFA
- Sandeep R Nair — AI/ML Engineer
