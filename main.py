# ──────────────────────────────
# FastAPI & Middleware Imports
from fastapi import FastAPI, Depends, HTTPException, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from fastapi.openapi.utils import get_openapi

# ──────────────────────────────
# SQLModel & Database Imports
from sqlmodel import select, Session, SQLModel
from db_connect.db import create_db_and_tables, engine, get_session, lifespan

# ──────────────────────────────
# Routers
from router.user_router import user_router

# ──────────────────────────────
# Utilities & Logging
from utils import del_pycache
from utils.loguru import cleanup_old_logs, logger
from utils.del_pycache import delete_pycache_folders

# ──────────────────────────────
# Other Standard Library Imports
from contextlib import asynccontextmanager
from datetime import datetime
import asyncio
import os

# ──────────────────────────────
# Third-party Libraries
from passlib.context import CryptContext
from dotenv import load_dotenv

load_dotenv()
# Call the function at startup (use your project root as argument)
delete_pycache_folders(os.path.dirname(os.path.abspath(__file__)))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 🔹 Startup Tasks
    print("Starting Application")
    print("Creating database and tables")
    create_db_and_tables()
    print("Database and tables created")

    logger.info("Starting application...")
    try:
        cleanup_old_logs()
        logger.info("Log cleanup process completed")
    except Exception as e:
        logger.error(f"Failed to clean up logs: {str(e)}")

    yield  # 🔸 Application Runs Here

    # 🔹 Shutdown Tasks
    logger.info("Application shutting down...")
    try:
        await engine.dispose()  # Close database connections
        
        # Cancel any pending tasks
        for task in asyncio.all_tasks():
            if not task.done():
                task.cancel()

        logger.info("Shutdown completed successfully")
    except Exception as e:
        logger.error(f"Shutdown error: {str(e)}")

origins = ["http://localhost:3000","https://mzbs.vercel.app"]

app = FastAPI(
    title="SCHOOL PRO BACKEND", 
    description="Manages all API for SCHOOL PRO BACKEND",
    version="0.1.0",
    openapi_url="/docs/json",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

logger.info("Starting application...")

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],  # Specify needed methods
    allow_headers=["Authorization", "Content-Type"],  # Specify needed headers
)

# Include the grouped router in the FastAPI app
app.include_router(user_router)


@app.get("/", tags=["Root"])
async def root():
    return {"Message": "School Pro Backend is running :-}"}

