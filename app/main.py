from fastapi import FastAPI
from app.db.init_db import init_db
from app.routes.auth import router as auth_router

app = FastAPI()

@app.on_event("startup")
def startup():
    init_db()

app.include_router(auth_router)

@app.get("/")
def health_check():
    return {"status": "VaultID backend running"}