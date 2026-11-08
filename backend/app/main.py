from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import text
from datetime import datetime

from app.core.config import settings
from app.db.session import engine, Base, get_db
import app.models  # Registers User, AuditLog, SecurityEvent, Alert models
from app.api.v1 import api_v1_router

app = FastAPI(
    title=settings.PROJECT_NAME,
    description="AI-Powered Security, Identity & Risk Intelligence Platform",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include API V1 routes
app.include_router(api_v1_router)


@app.on_event("startup")
def on_startup():
    # Initialize DB tables (creates SQLite tables automatically or PostgreSQL tables if configured)
    Base.metadata.create_all(bind=engine)


@app.get("/", tags=["General"])
def root():
    return {
        "message": f"Welcome to {settings.PROJECT_NAME} API",
        "description": "AI-Powered Security, Identity & Risk Intelligence Platform",
        "docs": "/docs",
        "status": "online",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health", tags=["Health"])
def health_check():
    return {
        "status": "ok",
        "service": "sentinel-ai-backend",
        "version": settings.VERSION,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/health/db", tags=["Health"])
def health_db_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        db_type = "sqlite" if settings.DATABASE_URL.startswith("sqlite") else "postgresql"
        return {
            "status": "healthy",
            "database": db_type,
            "connected": True,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database connection failed: {str(exc)}"
        )
