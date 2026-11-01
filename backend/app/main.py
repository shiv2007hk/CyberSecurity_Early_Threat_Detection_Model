"""CyberGuard AI — FastAPI application factory."""
import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .database import SessionLocal, init_db
from .seed import seed_if_empty
from .routers import (
    admin,
    alerts,
    analytics,
    assets,
    auth,
    chat,
    dashboard,
    exposure,
    public,
    recommendations,
    reports,
    scenarios,
    risk,
    search,
    sources,
    threats,
    vulnerabilities,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("aegis")

FRONTEND_DIST = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


@asynccontextmanager
async def lifespan(app: FastAPI):
    if settings.is_production and settings.jwt_secret_key.startswith("dev-only"):
        raise RuntimeError("JWT_SECRET_KEY must be set to a strong random value when APP_ENV=production")
    init_db()
    if settings.seed_intelligence_corpus:
        with SessionLocal() as db:
            if seed_if_empty(db):
                logger.info("Initial intelligence corpus seeded")
    logger.info("CyberGuard AI API ready (env=%s, live_feeds=%s)", settings.app_env, settings.enable_live_threat_feeds)
    yield


app = FastAPI(
    title="CyberGuard AI API",
    description=(
        "AI-driven cyber threat intelligence and risk analytics platform. "
        "Risk scores are deterministic and explainable; every record carries its source."
    ),
    version="1.0.0",
    docs_url=None if settings.is_production else "/api/docs",
    redoc_url=None if settings.is_production else "/api/redoc",
    openapi_url=None if settings.is_production else "/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
    max_age=600,
)
app.add_middleware(GZipMiddleware, minimum_size=1200)

_RATE_WINDOW = 60
_RATE_MAX = 600
_rate_buckets: dict[str, list[float]] = defaultdict(list)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if request.method == "POST" and request.url.path.startswith("/api"):
        content_length = request.headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > 5 * 1024 * 1024:
            return JSONResponse(status_code=413, content={"detail": "Request body exceeds the 5 MB limit"})
    if request.url.path.startswith("/api") and request.method != "OPTIONS":
        key = request.client.host if request.client else "unknown"
        now = time.time()
        bucket = _rate_buckets[key]
        while bucket and now - bucket[0] > _RATE_WINDOW:
            bucket.pop(0)
        if len(bucket) >= _RATE_MAX:
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Slow down and retry shortly."},
                headers={"Retry-After": "30"},
            )
        bucket.append(now)
    started = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    response.headers["X-Response-Time-Ms"] = str(int((time.perf_counter() - started) * 1000))
    if request.url.path.startswith("/api"):
        response.headers["Cache-Control"] = "no-store"
    return response


API_ROUTERS = [
    auth.router,
    public.router,
    dashboard.router,
    threats.router,
    vulnerabilities.router,
    assets.router,
    exposure.router,
    alerts.router,
    risk.router,
    recommendations.router,
    analytics.router,
    reports.router,
    sources.router,
    admin.router,
    chat.router,
    scenarios.router,
    search.router,
]

for api_router in API_ROUTERS:
    app.include_router(api_router, prefix="/api")


@app.get("/api", include_in_schema=False)
def api_index():
    return {
        "name": "CyberGuard AI API",
        "version": "1.0.0",
        "docs": None if settings.is_production else "/api/docs",
        "health": "/api/system/health",
    }


if (FRONTEND_DIST / "index.html").exists():
    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        if full_path.startswith(("api/", "api", "docs", "redoc", "openapi.json")):
            return JSONResponse(status_code=404, content={"detail": "Not found"})
        candidate = FRONTEND_DIST / full_path
        if full_path and candidate.is_file() and candidate.resolve().is_relative_to(FRONTEND_DIST.resolve()):
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
else:

    @app.get("/", include_in_schema=False)
    def root():
        return {
            "name": "CyberGuard AI API",
            "status": "running",
            "frontend": "Build the frontend with `npm run build` in /frontend, or run the Vite dev server.",
            "docs": None if settings.is_production else "/api/docs",
        }
