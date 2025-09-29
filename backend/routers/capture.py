# /opt/packetarena/backend/routers/capture.py
from fastapi import APIRouter, HTTPException
from settings import settings
from services.remote_capture import capture_once

router = APIRouter(prefix="", tags=["capture"])

@router.post("/remote/capture")
def remote_capture(payload: dict):
    host   = payload.get("host")
    iface  = payload.get("iface")
    dur    = int(payload.get("duration", 20))
    rpath  = payload.get("remote_path", "/tmp/packetarena_cap.pcap")
    sudo   = bool(payload.get("sudo", True))
    user   = payload.get("user", settings.SSH_USER)
    key    = payload.get("keyfile", settings.SSH_KEYFILE)

    if not host or not iface:
        raise HTTPException(400, "host, iface required")

    try:
        res = capture_once(host=host, user=user, keyfile=key, iface=iface,
                           duration_sec=dur, remote_path=rpath, sudo=sudo,
                           local_store_dir=settings.CAPTURE_DIR)
        return {"capture_id": res["capture_id"], "local_path": res["local_path"]}
    except Exception as e:
        raise HTTPException(500, f"remote capture failed: {e}")

