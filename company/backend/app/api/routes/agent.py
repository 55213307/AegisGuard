from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.endpoint import Endpoint
from app.services import screens

# Called by the screen agent running on monitored computers, not by the
# portal: it authenticates with the endpoint's own upload token instead of a
# portal login.
router = APIRouter(prefix="/api/agent", tags=["endpoint agent"])

_JPEG_MAGIC = b"\xff\xd8\xff"


@router.post("/screen")
async def upload_screen(
    request: Request,
    token: str = Header(alias="X-AegisGuard-Token"),
    db: Session = Depends(get_db),
) -> dict:
    endpoint_id = screens.token_endpoint_id(token)
    endpoint = db.get(Endpoint, endpoint_id) if endpoint_id is not None else None
    if endpoint is None or not screens.token_matches(token, endpoint.id, endpoint.wazuh_agent_id):
        raise HTTPException(status_code=401, detail="Invalid endpoint token")

    frame = await request.body()
    if len(frame) > screens.MAX_FRAME_BYTES:
        raise HTTPException(status_code=413, detail="Frame too large")
    if not frame.startswith(_JPEG_MAGIC):
        raise HTTPException(status_code=415, detail="Frames must be JPEG images")

    return {"next_interval": screens.store_frame(endpoint.id, frame)}
