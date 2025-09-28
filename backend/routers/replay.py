from fastapi import APIRouter, HTTPException
from services.tcpreplay_svc import start_replay

router = APIRouter(prefix="", tags=["replay"])
RUNNING = {}

@router.post("/replay/start")
def replay_start(payload: dict):
    pcap_path = payload.get("pcap_path")
    iface = payload.get("iface")
    mbps = payload.get("options",{}).get("mbps","10M")
    loop = int(payload.get("options",{}).get("loop",1))
    if not pcap_path or not iface: raise HTTPException(400, "pcap_path, iface required")
    proc = start_replay(pcap_path, iface, mbps=mbps, loop=loop)
    rid = str(len(RUNNING)+1)
    RUNNING[rid] = proc
    return {"replay_id": rid, "status":"running"}

@router.post("/replay/stop")
def replay_stop(payload: dict):
    rid = payload.get("replay_id")
    if rid not in RUNNING: raise HTTPException(404, "not running")
    proc = RUNNING.pop(rid)
    proc.terminate()
    return {"status":"stopped"}

