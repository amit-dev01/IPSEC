from fastapi import APIRouter

from ipsec_analyzer.api.v1.auth import router as auth_router
from ipsec_analyzer.api.v1.health import router as health_router
from ipsec_analyzer.api.v1.resources import router as resources_router

api_router = APIRouter()
api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(resources_router)
