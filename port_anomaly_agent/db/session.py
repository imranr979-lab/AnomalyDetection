"""
Database Session Factory
=========================
SQLAlchemy async + sync session management.
Connection pool sized for production load.
All credentials loaded from environment — never hardcoded.
"""

from contextlib import contextmanager, asynccontextmanager
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, Session

from config.settings import Settings

settings = Settings()

# Synchronous engine (for audit log writes — must be immediate)
_sync_engine = create_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    connect_args={"sslmode": "require"},  # TLS enforced
)

# Async engine (for result reads/writes)
_async_engine = create_async_engine(
    settings.database_url_async,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    connect_args={"ssl": "require"},
)

_SyncSession  = sessionmaker(bind=_sync_engine,  class_=Session,      expire_on_commit=False)
_AsyncSession = sessionmaker(bind=_async_engine, class_=AsyncSession, expire_on_commit=False)


@contextmanager
def get_sync_session():
    session = _SyncSession()
    try:
        yield session
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


@asynccontextmanager
async def get_async_session():
    async with _AsyncSession() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise
