from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse
from settings import settings
from services.suri_tail import sse_tail_eve
from services.ssh_tail import sse_tail_eve_remote

router = APIRouter(prefix="", tags=["logs"])

@router.get("/logs/suricata/stream")
def stream_logs(host: str | None = Query(default=None), sudo: bool = Query(default=False)):
    if host:
        gen = sse_tail_eve_remote(host=host, user=settings.SSH_USER, keyfile=settings.SSH_KEYFILE,
                                  eve_path=settings.REMOTE_EVE_PATH, sudo=sudo)
        return StreamingResponse(gen, media_type="text/event-stream")
    return StreamingResponse(sse_tail_eve(settings.EVE_PATH), media_type="text/event-stream")

