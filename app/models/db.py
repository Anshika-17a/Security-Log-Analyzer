import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv
from app.models.schema import Base

load_dotenv()

RAW_DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./logs.db")


def normalise_url(url: str) -> str:
    """Return a URL SQLAlchemy 2.x can actually open.

    Managed Postgres providers (Render, Heroku, Railway) hand out URLs starting
    with 'postgres://', a scheme SQLAlchemy 2 removed. Bare 'postgresql://' also
    resolves to psycopg2, which we do not ship. Both are rewritten to psycopg v3.
    An explicit driver (e.g. 'postgresql+asyncpg://') is left untouched.
    """
    if url.startswith("postgres://"):
        return "postgresql+psycopg://" + url[len("postgres://"):]
    if url.startswith("postgresql://"):
        return "postgresql+psycopg://" + url[len("postgresql://"):]
    return url


DATABASE_URL = normalise_url(RAW_DATABASE_URL)

if DATABASE_URL.startswith("sqlite"):
    # SQLite only: allow use across FastAPI's threadpool.
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    # Managed Postgres closes idle connections and free tiers cap them low, so
    # revalidate before use and keep the pool small.
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=5,
        max_overflow=5,
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
