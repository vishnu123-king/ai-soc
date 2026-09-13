import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./soc_database.db")

engine = create_engine(
    DB_PATH, connect_args={"check_same_thread": False} if "sqlite" in DB_PATH else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
