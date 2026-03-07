from pydantic_settings import BaseSettings


class Settings(BaseSettings):

    SECRET_KEY: str = "super-secret-key-change-this"
    ALGORITHM: str = "HS256"

    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7


settings = Settings()