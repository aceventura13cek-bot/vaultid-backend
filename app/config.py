import os
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg2://vaultdev:vaultdev123@localhost:5432/vaultid_dev")
    
    # JWT Settings
    SECRET_KEY: str = os.getenv("SECRET_KEY", "devsecretkey-change-in-production")
    ALGORITHM: str = "HS256"  # ✅ Add this line if missing
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # ZKP Settings
    ZKP_KEY_SIZE: int = 2048
    ZKP_CHALLENGE_EXPIRY: int = 300
    
    class Config:
        env_file = ".env"

settings = Settings()