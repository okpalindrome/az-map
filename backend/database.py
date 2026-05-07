from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, DeclarativeBase

from .config import settings

engine = create_engine(
    f"sqlite:///{settings.db_path}",
    connect_args={"check_same_thread": False},
    echo=False,
)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_conn, _rec):
    """
    WAL mode: allows concurrent reads alongside a single writer — eliminates
    'database is locked' errors when the scan background task and the API
    handler open separate sessions simultaneously.

    busy_timeout: instead of immediately raising OperationalError on a lock,
    SQLite retries for up to 15 seconds. Belt-and-suspenders on top of WAL.
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=15000")
    cursor.execute("PRAGMA synchronous=NORMAL")   # safe with WAL, much faster
    cursor.execute("PRAGMA cache_size=-32000")     # 32 MB page cache
    cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401 — ensure models are imported before create_all
    Base.metadata.create_all(bind=engine)
