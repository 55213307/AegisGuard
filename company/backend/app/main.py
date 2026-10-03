from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.api.routes import agent, auth, employees
from app.core.config import settings

app = FastAPI(title="AegisGuard Company Portal API")


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

# Frontend lives at AegisGuard/company/frontend and references shared assets
# at AegisGuard/resources via "../../resources".
app.mount("/resources", StaticFiles(directory="../../resources"), name="resources")

# Mounted last so the /api/* routes above take priority.
app.mount("/", StaticFiles(directory=settings.frontend_dir, html=True), name="frontend")
