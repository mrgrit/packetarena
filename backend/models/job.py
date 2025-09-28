import uuid, datetime as dt
from sqlalchemy import Column, String, Text, DateTime, Integer
from .base import Base

class PacketJob(Base):
    __tablename__ = "packet_jobs"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    template_id = Column(String)
    variables = Column(Text)           # JSON str
    pcap_path = Column(String)
    status = Column(String, default="pending")  # pending|success|failed
    message = Column(Text)
    packet_count = Column(Integer)
    preview_hex = Column(Text)
    preview_summary = Column(Text)
    created_at = Column(DateTime, default=dt.datetime.utcnow)
    updated_at = Column(DateTime, default=dt.datetime.utcnow, onupdate=dt.datetime.utcnow)

