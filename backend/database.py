from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import shutil

# Store all persistent data under repository root ./data
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(ROOT_DIR, "data")
os.makedirs(DB_DIR, exist_ok=True)

DB_FILENAME = "analysis.db"
DB_PATH = os.path.join(DB_DIR, DB_FILENAME)


def _legacy_db_path() -> str:
    """Resolve legacy DB path from backend/data/analysis.db."""
    legacy_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
    return os.path.join(legacy_dir, DB_FILENAME)


def _migrate_legacy_db_if_needed() -> None:
    """One-time migration of legacy DB into the shared data directory.

    Refactor note: isolate migration side effects for readability.
    """
    legacy_path = _legacy_db_path()
    if os.path.exists(DB_PATH) or not os.path.exists(legacy_path):
        return

    os.makedirs(DB_DIR, exist_ok=True)
    try:
        shutil.copy2(legacy_path, DB_PATH)
    except Exception:
        # If copy fails, we'll just create a fresh DB file.
        pass


_migrate_legacy_db_if_needed()

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
