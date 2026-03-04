from fastapi import FastAPI
from sqlalchemy import text
from app.config import settings
from app.db.session import engine

app = FastAPI()


@app.on_event("startup")
def test_database_connection():
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        print("Database connection successful.")
    except Exception as e:
        print("Database connection failed.")
        raise e


@app.get("/")
def health_check():
    return {
        "status": "VaultID backend running",
        "db_url_loaded": bool(settings.DATABASE_URL)
    }