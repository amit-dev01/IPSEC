import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ipsec_analyzer.api.v1.router import api_router
from ipsec_analyzer.core.config import Settings, get_settings
from ipsec_analyzer.core.logging import configure_logging
from ipsec_analyzer.core.ratelimit import LoginRateLimiter
from ipsec_analyzer.db.session import engine
from ipsec_analyzer.services.dispatch import CeleryDispatcher
from ipsec_analyzer.storage.s3 import S3Storage

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    configure_logging(settings.log_level)
    logger.info("application startup (environment=%s)", settings.environment)
    yield
    engine.dispose()
    logger.info("application shutdown")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved = settings or get_settings()
    docs = resolved.docs_enabled
    app = FastAPI(
        title="IPsec Analyzer",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/docs" if docs else None,
        redoc_url="/redoc" if docs else None,
        openapi_url="/openapi.json" if docs else None,
    )
    app.state.settings = resolved
    app.state.storage = S3Storage(resolved)  # lazy boto client; tests may override
    app.state.dispatcher = CeleryDispatcher().enqueue
    app.state.login_rate_limiter = LoginRateLimiter(
        resolved.login_max_attempts, resolved.login_window_seconds
    )
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
