import secrets
import time

ACCESS_TOKEN_LIFE = 300        # 5 minutes
REFRESH_TOKEN_LIFE = 86400     # 1 day (demo)

def generate_access_token():
    return secrets.token_urlsafe(32)

def generate_refresh_token():
    return secrets.token_urlsafe(48)
