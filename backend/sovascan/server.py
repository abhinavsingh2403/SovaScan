"""FastAPI application entry point for SovaScan API."""

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sovascan import __version__
from sovascan.api.routes import router
from sovascan.api.websocket import scan_websocket
from sovascan.config import get_settings
from sovascan.models.base import init_db

logger = logging.getLogger("sovascan")

_start_time: float = 0.0


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager.

    Handles startup and shutdown events:
    - Startup: initializes the database tables and logs readiness.
    - Shutdown: performs any cleanup needed.
    """
    global _start_time
    _start_time = time.time()

    settings = get_settings()
    logger.info("Starting SovaScan API v%s", __version__)
    logger.info("Database URL: %s", settings.DATABASE_URL)
    logger.info("Debug mode: %s", settings.DEBUG)

    # Initialize database tables
    init_db()
    logger.info("Database initialized successfully")

    yield

    logger.info("Shutting down SovaScan API")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.

    Returns:
        FastAPI: The configured application instance.
    """
    application = FastAPI(
        title="SovaScan API",
        version=__version__,
        description=(
            "SovaScan is a security vulnerability scanner and compliance checker. "
            "It provides endpoints for scanning projects, generating SBOMs, "
            "checking compliance against frameworks, and auto-fixing findings."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # CORS middleware — allow configured origins
    settings = get_settings()
    allow_origins = settings.ALLOWED_ORIGINS
    allow_credentials = True
    if "*" in allow_origins:
        allow_credentials = False

    application.add_middleware(
        CORSMiddleware,
        allow_origins=allow_origins,
        allow_credentials=allow_credentials,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API v1 router
    application.include_router(router, prefix="/api/v1")

    # WebSocket endpoint for real-time scan progress streaming
    application.add_api_websocket_route("/api/v1/scan/{scan_id}/ws", scan_websocket)

    @application.get("/health", tags=["system"])
    async def health_check() -> dict:
        """Health check endpoint.

        Returns:
            dict: Health status including version, database status, and scanner availability.
        """
        uptime = time.time() - _start_time if _start_time > 0 else 0.0

        # Check database health
        db_status = "ok"
        try:
            from sovascan.models.base import SessionLocal
            from sovascan.models.scan import Scan
            db = SessionLocal()
            db.query(Scan).first()
            db.close()
        except Exception as e:
            logger.warning(f"Health check database connection check failed: {e}")
            db_status = "error"

        # Check scanner CLI availability
        import shutil
        scanners = {
            "semgrep": shutil.which("semgrep") is not None,
            "bandit": shutil.which("bandit") is not None,
            "git": shutil.which("git") is not None,
        }

        return {
            "status": "healthy" if db_status == "ok" else "degraded",
            "version": __version__,
            "database": db_status,
            "scanners": scanners,
            "uptime": round(uptime, 2),
        }

    # Mount static frontend React dashboard if built
    import os

    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles

    dist_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../frontend/dist"))
    if os.path.exists(dist_dir):
        assets_dir = os.path.join(dist_dir, "assets")
        if os.path.exists(assets_dir):
            application.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

        @application.get("/{catchall:path}", tags=["frontend"])
        async def serve_spa(catchall: str):
            if catchall.startswith("api/") or catchall.startswith("docs") or catchall.startswith("redoc") or catchall.startswith("health"):
                from fastapi.responses import JSONResponse
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            return FileResponse(os.path.join(dist_dir, "index.html"))

    return application


# Module-level app instance for uvicorn
app = create_app()


def main() -> None:
    """Run the SovaScan API server via uvicorn.

    Reads host and port from application settings.
    """
    logging.basicConfig(
        level=logging.DEBUG if get_settings().DEBUG else logging.INFO,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    )

    settings = get_settings()
    uvicorn.run(
        "sovascan.server:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level="debug" if settings.DEBUG else "info",
    )


if __name__ == "__main__":
    main()
