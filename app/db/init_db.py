from app.db.base import Base
from app.db.session import engine

# Import models so metadata registers them
from app.models.user import User  # noqa


def init_db():
    Base.metadata.create_all(bind=engine)