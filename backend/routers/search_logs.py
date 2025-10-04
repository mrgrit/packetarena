from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from deps import get_db
from models.suri_event import SuricataEvent
from models.replay_session import ReplaySession
import datetime as dt
import json

router = APIRouter(prefix="", tags=["logs-search"])

@router.get("/logs/search")
def search_logs(
    time_from: str | None = Query(None, description="ISO8601 (e.g. 2025-09-29T00:00:00Z)"),
    time_to:   str | None = Query(None),
    src_ip:    str | None = Query(None),
    dst_ip:    str | None = Query(None),
    sid:       int | None = Query(None),
    replay_id: str | None = Query(None),
    limit:     int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
):
    q = db.query(SuricataEvent)
    if time_from:
        q = q.filter(SuricataEvent.ts >= dt.datetime.fromisoformat(time_from.replace("Z","+00:00")))
    if time_to:
        q = q.filter(SuricataEvent.ts <= dt.datetime.fromisoformat(time_to.replace("Z","+00:00")))
    if src_ip:
        q = q.filter(SuricataEvent.src_ip == src_ip)
    if dst_ip:
        q = q.filter(SuricataEvent.dst_ip == dst_ip)
    if sid:
        q = q.filter(SuricataEvent.signature_id == sid)

    # 리플레이 세션과 상관관계: 세션 변수(가능하면 src/dst) + 시간창(시작~끝+약간 여유)
    if replay_id:
        s = db.query(ReplaySession).get(replay_id)
        if s:
            # 시간창 설정
            t0 = s.started_at
            t1 = s.ended_at or (t0 + dt.timedelta(minutes=5))
            q = q.filter(SuricataEvent.ts >= t0, SuricataEvent.ts <= t1)
            # 변수에 src/dst가 있으면 추가 필터
            try:
                v = json.loads(s.variables) if s.variables else {}
                if "src_ip" in v: q = q.filter(SuricataEvent.src_ip == v["src_ip"])
                if "dst_ip" in v: q = q.filter(SuricataEvent.dst_ip == v["dst_ip"])
            except Exception:
                pass

    q = q.order_by(SuricataEvent.ts.desc()).limit(limit)
    rows = q.all()
    return [
        {
            "ts": r.ts.isoformat(),
            "src_ip": r.src_ip, "src_port": r.src_port,
            "dst_ip": r.dst_ip, "dst_port": r.dst_port,
            "proto": r.proto, "sig": r.signature, "sid": r.signature_id,
            "sev": r.severity
        } for r in rows
    ]
