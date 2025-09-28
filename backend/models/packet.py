import datetime as dt
from sqlalchemy import Column, String, Text, Boolean, DateTime

from .base import Base

class PacketTemplate(Base):
    __tablename__ = "packet_templates"
    id = Column(String, primary_key=True)  # pkt-syn / pkt-sqli / pkt-icmp
    name = Column(String, nullable=False)
    category = Column(String, nullable=False)
    risk = Column(String, nullable=False)
    description = Column(Text)
    variables_spec = Column(Text)  # JSON str (간단히 문자열로 보관)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=dt.datetime.utcnow)

