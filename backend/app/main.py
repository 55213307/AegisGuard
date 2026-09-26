from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.api.routes import accounts, auth, customers, dashboard
from app.core.config import settings

app = FastAPI(title="AegisGuard API")

# Dev-time convenience: the frontend is served by this same app (see the
# static mount below), so CORS normally isn't needed. This stays permissive
# only for local tools (e.g. hitting the API directly while iterating).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(customers.router)
app.include_router(accounts.router)

# The frontend HTML references shared assets (e.g. the logo) via "../resources",
# one level above the frontend dir, so that path must be served too.
app.mount("/resources", StaticFiles(directory=f"{settings.frontend_dir}/../resources"), name="resources")

# Serves the existing plain HTML/CSS/JS frontend (AegisGuard/frontend) as
# static files, per the IR's chosen architecture (FastAPI + static/Jinja2
# hosting instead of a separate frontend server). Must be mounted last so
# the /api/* routes above take priority.
app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")
