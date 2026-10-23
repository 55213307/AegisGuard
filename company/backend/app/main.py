import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.api.routes import agent, anomalies, auth, dashboard, employees, security_logs
from app.core.config import settings
from app.services import health, ingest
from app.services.ml import registry as ml_registry

# uvicorn only sets up logging for its own loggers, so without this the
# background workers' INFO lines (ingestion, model training) never reach the
# journal; only warnings and errors would.
_app_log = logging.getLogger("aegisguard")
if not _app_log.handlers:
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("%(levelname)s:     %(name)s - %(message)s"))
    _app_log.addHandler(_handler)
_app_log.setLevel(logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    ingest.start()
    ml_registry.start()
    try:
        yield
    finally:
        ml_registry.stop()
        ingest.stop()


app = FastAPI(title="AegisGuard Company Portal API", lifespan=lifespan)


@app.middleware("http")
async def track_server_errors(request: Request, call_next):
    # Unhandled errors in API routes end as a 500 and nothing else notices them;
    # the dashboard's Platform Service Status shows them (services/health.py).
    try:
        response = await call_next(request)
    except Exception as exc:
        if request.url.path.startswith("/api/"):
            health.fail("api", f"{request.method} {request.url.path}: {type(exc).__name__}")
        raise
    if response.status_code >= 500 and request.url.path.startswith("/api/"):
        health.fail("api", f"{request.method} {request.url.path} answered {response.status_code}")
    return response


@app.middleware("http")
async def revalidate_frontend_files(request: Request, call_next):
    # Without this, browsers cache the portal's JS/CSS/HTML heuristically and
    # keep running old code after a deploy. "no-cache" still lets them reuse
    # their copy, but only after a quick 304 check with the server.
    response = await call_next(request)
    if not request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-cache")
    return response


app.include_router(auth.router)
app.include_router(employees.router)
app.include_router(agent.router)
app.include_router(dashboard.router)
app.include_router(security_logs.router)
app.include_router(anomalies.router)

# Frontend lives at AegisGuard/company/frontend and references shared assets
# at AegisGuard/resources via "../../resources".
app.mount("/resources", StaticFiles(directory="../../resources"), name="resources")

# Mounted last so the /api/* routes above take priority.
app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")
