from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from services.tcpreplay_svc import start_replay
from models.replay_session import ReplaySession
from models.job import PacketJob
from deps import get_db

router = APIRouter(prefix="", tags=["replay"])
RUNNING = {}  # replay_id -> Popen

@router.post("/replay/start")
def replay_start(payload: dict, db: Session = Depends(get_db)):
    pcap_path = payload.get("pcap_path")
    iface = payload.get("iface")
    mbps = payload.get("options",{}).get("mbps","10M")
    loop = int(payload.get("options",{}).get("loop",1))
    if not pcap_path or not iface: raise HTTPException(400, "pcap_path, iface required")

    # 세션 기록 (job 정보 있으면 함께)
    job = db.query(PacketJob).filter(PacketJob.pcap_path==pcap_path).order_by(PacketJob.created_at.desc()).first()
    sess = ReplaySession(pcap_path=pcap_path, iface=iface,
                         template_id=(job.template_id if job else None),
                         variables=(job.variables if job else None))
    db.add(sess); db.commit()

    proc = start_replay(pcap_path, iface, mbps=mbps, loop=loop)
    RUNNING[sess.id] = proc
    return {"replay_id": sess.id, "status":"running"}

@router.post("/replay/stop")
def replay_stop(payload: dict, db: Session = Depends(get_db)):
    rid = payload.get("replay_id")
    if rid not in RUNNING: raise HTTPException(404, "not running")
    RUNNING.pop(rid).terminate()
    # ended_at 업데이트(옵션)
    s = db.query(ReplaySession).get(rid)
    if s:
        import datetime as dt
        s.ended_at = dt.datetime.utcnow(); db.commit()
    return {"status":"stopped"}
