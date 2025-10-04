import json, datetime as dt
from typing import Iterable, List
from sqlalchemy.orm import Session
from models.suri_event import SuricataEvent

def parse_ts(s: str) -> dt.datetime:
    # Suricata는 "2025-01-02T03:04:05.678901+0000" 또는 "+00:00" 형태
    try:
        # Python 3.11+: fromisoformat가 대부분 처리
        return dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        # 실패 시 UTC로 무조건 파싱 시도
        return dt.datetime.strptime(s.split(".")[0], "%Y-%m-%dT%H:%M:%S")

def bulk_index_events(db: Session, lines: Iterable[str], min_ts: dt.datetime | None = None) -> int:
    """
    lines: eve.json JSONL 라인들
    min_ts: 이 시각 이전 이벤트는 스킵(옵션)
    return: 삽입 건수
    """
    cnt = 0
    for line in lines:
        line = line.strip()
        if not line: continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        if obj.get("event_type") != "alert":
            continue
        ts = parse_ts(obj["timestamp"])
        if min_ts and ts < min_ts:
            continue
        src_ip  = obj.get("src_ip");  dst_ip  = obj.get("dst_ip")
        src_p   = obj.get("src_port"); dst_p  = obj.get("dst_port")
        proto   = obj.get("proto")
        sig     = (obj.get("alert") or {}).get("signature")
        sid     = (obj.get("alert") or {}).get("signature_id")
        sev     = (obj.get("alert") or {}).get("severity")
        ev = SuricataEvent(ts=ts, src_ip=src_ip, src_port=src_p,
                           dst_ip=dst_ip, dst_port=dst_p, proto=proto,
                           signature=sig, signature_id=sid, severity=sev, raw=obj)
        db.add(ev)
        cnt += 1
        if cnt % 500 == 0:
            db.commit()
    db.commit()
    return cnt
