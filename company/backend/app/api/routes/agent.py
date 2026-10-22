from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.services import endpoint_lock, screens

# Called by the screen agent running on monitored computers, not by the
# portal: it authenticates with the endpoint's own upload token instead of a
# portal login.
router = APIRouter(prefix="/api/agent", tags=["endpoint agent"])

_JPEG_MAGIC = b"\xff\xd8\xff"


def _authenticated_endpoint(token: str, db: Session) -> Endpoint:
    endpoint_id = screens.token_endpoint_id(token)
    endpoint = db.get(Endpoint, endpoint_id) if endpoint_id is not None else None
    if endpoint is None or not screens.token_matches(token, endpoint.id, endpoint.wazuh_agent_id):
        raise HTTPException(status_code=401, detail="Invalid endpoint token")
    return endpoint


@router.get("/status")
def status(
    token: str = Header(alias="X-AegisGuard-Token"),
    db: Session = Depends(get_db),
) -> dict:
    """Polled by the screen agent every few seconds: whether this computer is
    locked. The state is the employee account's, set in the portal or by a
    Critical event, so the computer can't unlock itself."""
    endpoint = _authenticated_endpoint(token, db)
    return {"locked": endpoint_lock.is_locked(endpoint.employee)}


@router.post("/maintenance")
def maintenance(
    token: str = Header(alias="X-AegisGuard-Token"),
    db: Session = Depends(get_db),
) -> dict:
    """Called by the installer as it starts: for a while the computer's events
    aren't judged, so the installer's own PowerShell/registry work can't be
    mistaken for an attack and lock the computer it is installing on."""
    endpoint = _authenticated_endpoint(token, db)
    until = endpoint_lock.begin_maintenance(db, endpoint)
    return {"maintenance_until": until.isoformat()}


@router.post("/screen")
async def upload_screen(
    request: Request,
    token: str = Header(alias="X-AegisGuard-Token"),
    db: Session = Depends(get_db),
) -> dict:
    endpoint = _authenticated_endpoint(token, db)

    frame = await request.body()
    if len(frame) > screens.MAX_FRAME_BYTES:
        raise HTTPException(status_code=413, detail="Frame too large")
    if not frame.startswith(_JPEG_MAGIC):
        raise HTTPException(status_code=415, detail="Frames must be JPEG images")

    return {"next_interval": screens.store_frame(endpoint.id, frame)}
