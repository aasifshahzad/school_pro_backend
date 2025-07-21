from contextlib import asynccontextmanager
from fastapi import FastAPI
from sqlmodel import SQLModel, create_engine, Session
from utils.loguru import logger
from db_connect import settings

CONN_STRING: str = str(settings.DATABASE_URL)

def get_engine(CONN_STRING):
    engine = create_engine(CONN_STRING, echo=True, connect_args={}, pool_recycle=300)
    logger.info("Engine created successfully")
    return engine

engine = get_engine(CONN_STRING=CONN_STRING)

# Add SessionLocal
SessionLocal = Session

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Creating database connection")
    try:
        create_db_and_tables()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {str(e)}")
        raise
    yield
    logger.info("Closing database connection")

def get_session():
    with SessionLocal(engine) as session:
        try:
            yield session
        finally:
            session.close()