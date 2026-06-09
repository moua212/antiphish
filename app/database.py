# app/database.py

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker
)
from sqlalchemy.orm import DeclarativeBase
import os


# -----------------------------------
# Database URL
# -----------------------------------
POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
POSTGRES_DB = os.getenv("POSTGRES_DB", "phishing_db")
POSTGRES_HOST = os.getenv("POSTGRES_HOST", "db")  # docker service name
POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")

DATABASE_URL = (
    f"postgresql+asyncpg://"
    f"{POSTGRES_USER}:{POSTGRES_PASSWORD}"
    f"@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"
)


# -----------------------------------
# Engine
# -----------------------------------
engine = create_async_engine(
    DATABASE_URL,
    echo=True,      # False in production
    future=True
)


# -----------------------------------
# Session Factory
# -----------------------------------
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False
)


# -----------------------------------
# Base model
# -----------------------------------
class Base(DeclarativeBase):
    pass


# -----------------------------------
# Dependency for FastAPI
# -----------------------------------
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    from app import models  # enregistre les modèles dans Base.metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)  # CREATE TABLE IF NOT EXISTS



        