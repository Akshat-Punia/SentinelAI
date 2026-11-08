from fastapi import APIRouter
from app.api.v1.auth import router as auth_router
from app.api.v1.users import router as users_router
from app.api.v1.events import router as events_router
from app.api.v1.alerts import router as alerts_router
from app.api.v1.ml import router as ml_router
from app.api.v1.assistant import router as assistant_router
from app.api.v1.analytics import router as analytics_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(auth_router)
api_v1_router.include_router(users_router)
api_v1_router.include_router(events_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(ml_router)
api_v1_router.include_router(assistant_router)
api_v1_router.include_router(analytics_router)
