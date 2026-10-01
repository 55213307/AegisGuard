from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.api.routes import auth, employees
from app.core.config import settings

app = FastAPI(title="AegisGuard Company Portal API")

app.include_router(auth.router)
app.include_router(employees.router)

# Frontend lives at AegisGuard/company/frontend and references shared assets
# at AegisGuard/resources via "../../resources".
app.mount("/resources", StaticFiles(directory="../../resources"), name="resources")

# Mounted last so the /api/* routes above take priority.
app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")
