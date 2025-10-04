import uuid, datetime as dt, json
from sqlalchemy import Column, String, DateTime, Text
from .base import Base

class ReplaySession(Base):
    __tablename__ = "replay_sessions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    pcap_path = Column(Text, nullable=False)
    template_id = Column(String)
    variables = Column(Text)  # JSON str (src_ip, dst_ip 등)
    iface = Column(String)
    started_at = Column(DateTime, default=dt.datetime.utcnow, nullable=False)
    ended_at = Column(DateTime)  # (옵션) stop 시나 프로세스 종료 시 기록
