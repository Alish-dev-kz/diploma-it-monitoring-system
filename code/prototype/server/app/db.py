"""Подключение к БД. По умолчанию SQLite; для PostgreSQL задайте
ITMON_DB_URL=postgresql+psycopg2://user:pass@host/dbname"""
import os
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

DB_URL = os.environ.get("ITMON_DB_URL", "sqlite:///" + os.path.join(os.path.dirname(os.path.dirname(__file__)), "itmon.db"))
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# columns added after the first release: (table, column, DDL type)
_NEW_COLUMNS = [
    ("commands", "expires_at", "FLOAT"),
    ("commands", "attempts", "INTEGER NOT NULL DEFAULT 0"),
    ("commands", "started_at", "FLOAT"),
    ("commands", "finished_at", "FLOAT"),
]


def migrate():
    """Minimal migration for existing databases (create_all does not add columns)."""
    insp = inspect(engine)
    with engine.begin() as conn:
        for table, column, ddl in _NEW_COLUMNS:
            if table in insp.get_table_names() and column not in {c["name"] for c in insp.get_columns(table)}:
                conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
