import datetime as dt
from sqlalchemy import Column, Integer, String, DateTime, JSON
from .base import Base

class SuricataEvent(Base):
    __tablename__ = "suricata_events"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, index=True, nullable=False)
    src_ip = Column(String, index=True)
    src_port = Column(Integer)
    dst_ip = Column(String, index=True)
    dst_port = Column(Integer)
    proto = Column(String)
    signature = Column(String, index=True)
    signature_id = Column(Integer, index=True)
    severity = Column(Integer)
    raw = Column(JSON)  # eve.json 한 줄 그대로
