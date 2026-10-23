import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from ipsec_analyzer.api.v1.router import api_router
from ipsec_analyzer.core.config import Settings, get_settings
from ipsec_analyzer.core.logging import configure_logging
from ipsec_analyzer.db.session import engine

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
    app = FastAPI(title="IPsec Analyzer", version="0.1.0", lifespan=lifespan)
    app.state.settings = settings or get_settings()
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
