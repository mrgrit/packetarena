import os, json
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from settings import settings
from deps import engine, SessionLocal
from models.base import Base
from models.packet import PacketTemplate
#from routers import packets, replay, logs
from routers.packets import router as packets_router
from routers.replay import router as replay_router
from routers.logs import router as logs_router

Base.metadata.create_all(bind=engine)
os.makedirs(settings.PCAP_DIR, exist_ok=True)

# 템플릿 자동 시드 (없을 때만)
def seed_templates():
    db = SessionLocal()
    try:
        existing = {t.id for t in db.query(PacketTemplate).all()}
        seeds = [
            ("pkt-syn","TCP SYN Scan (burst)","scan","low","빠른 SYN 포트 스캔", '{"src_ip":"ip","dst_ip":"ip","dst_port":"int","count":"int"}'),
            ("pkt-sqli","HTTP SQLi (union select)","web-app","medium","HTTP 요청에 union select 포함", '{"src_ip":"ip","dst_ip":"ip","dst_port":"int","count":"int"}'),
            ("pkt-icmp","ICMP Echo (ping burst)","network","low","ICMP ping burst", '{"src_ip":"ip","dst_ip":"ip","count":"int"}'),
        ]
        for tid, name, cat, risk, desc, spec in seeds:
            if tid not in existing:
                db.add(PacketTemplate(id=tid, name=name, category=cat, risk=risk, description=desc, variables_spec=spec))
        db.commit()
    finally:
        db.close()
seed_templates()

app = FastAPI(title=settings.APP_NAME)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)
#app.include_router(packets.router, prefix="/api/v1")
#app.include_router(replay.router,  prefix="/api/v1")
#app.include_router(logs.router,    prefix="/api/v1")
app.include_router(packets_router, prefix="/api/v1")
app.include_router(replay_router,  prefix="/api/v1")
app.include_router(logs_router,    prefix="/api/v1")

@app.get("/api/v1/health")
def health():
    return {"ok": True}

