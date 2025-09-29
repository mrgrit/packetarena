# /opt/packetarena/backend/routers/rewrite.py
from fastapi import APIRouter, HTTPException
from settings import settings
from services.rewrite_svc import tcprewrite_rewrite
import os, uuid

router = APIRouter(prefix="", tags=["rewrite"])

@router.post("/packets/rewrite")
def rewrite(payload: dict):
    in_pcap   = payload.get("pcap_path")
    src_ipmap = payload.get("src_ipmap")   # "old:new"
    dst_ipmap = payload.get("dst_ipmap")
    sportmap  = payload.get("sportmap")    # "80:8080"
    dportmap  = payload.get("dportmap")
    mtu       = payload.get("mtu")
    if not in_pcap or not os.path.exists(in_pcap):
        raise HTTPException(400, "valid pcap_path required")

    out_path = os.path.join(settings.REWRITE_DIR, f"{uuid.uuid4()}.pcap")
    try:
        res = tcprewrite_rewrite(in_pcap, out_path, src_ipmap, dst_ipmap, sportmap, dportmap, mtu)
        return {"rewritten_pcap": res["outfile"], "log": res["output"]}
    except Exception as e:
        raise HTTPException(500, str(e))

