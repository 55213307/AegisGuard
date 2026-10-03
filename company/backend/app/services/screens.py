"""Latest screen frame per endpoint, for the portal's live view.

Frames are kept in memory only (one per endpoint, overwritten each upload):
there's no screen history on disk or in the database. The service runs as a
single uvicorn worker, so a module-level store is shared by all requests.
"""

import hashlib
import hmac
import threading
import time

from app.core.config import settings

# While someone has the live view open, agents upload every second;
# otherwise every 10 seconds, which is enough for the overview thumbnails.
LIVE_INTERVAL_SECONDS = 1
IDLE_INTERVAL_SECONDS = 10
LIVE_VIEW_TIMEOUT_SECONDS = 15
MAX_FRAME_BYTES = 2 * 1024 * 1024

_lock = threading.Lock()
_frames: dict[int, tuple[bytes, float]] = {}
_live_viewed_at: dict[int, float] = {}


def screen_token(endpoint_id: int, wazuh_agent_id: str) -> str:
    """The upload token embedded in an endpoint's installer. Derived rather
    than stored: it's stable across re-downloads, and stops working as soon
    as the endpoint is deleted or re-registered with a new agent."""
    message = f"screen:{endpoint_id}:{wazuh_agent_id}".encode()
    digest = hmac.new(settings.jwt_secret_key.encode(), message, hashlib.sha256).hexdigest()
    return f"{endpoint_id}.{digest}"


def token_endpoint_id(token: str) -> int | None:
    """The endpoint id a token claims to be for (still to be verified)."""
    endpoint_id, _, _ = token.partition(".")
    return int(endpoint_id) if endpoint_id.isdigit() else None


def token_matches(token: str, endpoint_id: int, wazuh_agent_id: str) -> bool:
    return hmac.compare_digest(token, screen_token(endpoint_id, wazuh_agent_id))


def store_frame(endpoint_id: int, frame: bytes) -> int:
    """Saves the frame and returns how many seconds the agent should wait
    before sending the next one."""
    now = time.time()
    with _lock:
        _frames[endpoint_id] = (frame, now)
        watched = now - _live_viewed_at.get(endpoint_id, 0) < LIVE_VIEW_TIMEOUT_SECONDS
    return LIVE_INTERVAL_SECONDS if watched else IDLE_INTERVAL_SECONDS


def latest_frame(endpoint_id: int, live: bool) -> tuple[bytes, float] | None:
    """The newest frame and when it arrived. live=True means someone has the
    full-size view open, which switches the agent to its fast rate."""
    with _lock:
        if live:
            _live_viewed_at[endpoint_id] = time.time()
        return _frames.get(endpoint_id)


def forget(endpoint_id: int) -> None:
    with _lock:
        _frames.pop(endpoint_id, None)
        _live_viewed_at.pop(endpoint_id, None)
