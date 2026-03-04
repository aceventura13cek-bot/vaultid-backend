from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.config import settings

# Create SQLAlchemy engine
engine = create_engine(
    settings.DATABASE_URL,
    echo=True,  # Shows SQL logs (good for dev)
    future=True
)

# Create session factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Dependency (used later in routes)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()