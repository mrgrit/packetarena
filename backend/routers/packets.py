import json, os, uuid
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from models.packet import PacketTemplate
from models.job import PacketJob
from deps import get_db
from settings import settings
from services.scapy_gen import generate_pcap

router = APIRouter(prefix="", tags=["packets"])

@router.get("/packets")
def list_templates(db: Session = Depends(get_db)):
    q = db.query(PacketTemplate).filter(PacketTemplate.is_active==True).all()
    return [{"id": t.id, "name": t.name, "category": t.category, "risk": t.risk, "description": t.description} for t in q]

@router.post("/packets/generate")
def gen_packet(payload: dict, db: Session = Depends(get_db)):
    template_id = payload.get("template_id")
    variables = payload.get("variables", {})
    if not template_id: raise HTTPException(400, "template_id required")
    job_id = str(uuid.uuid4())
    out_path = os.path.join(settings.PCAP_DIR, f"{job_id}.pcap")
    try:
        res = generate_pcap(template_id, variables, out_path)
        job = PacketJob(
            id=job_id, template_id=template_id, variables=json.dumps(variables),
            pcap_path=res["pcap_path"], status="success",
            packet_count=res["packet_count"], preview_hex=res["preview_hex"], preview_summary=res["preview_summary"]
        )
        db.add(job); db.commit()
        return {"job_id": job_id, **res}
    except Exception as e:
        db.add(PacketJob(id=job_id, template_id=template_id, variables=json.dumps(variables), status="failed", message=str(e)))
        db.commit()
        raise HTTPException(500, f"generation failed: {e}")

@router.get("/packets/preview/{job_id}")
def preview(job_id: str, db: Session = Depends(get_db)):
    job = db.query(PacketJob).get(job_id)
    if not job: raise HTTPException(404, "not found")
    return {"hex": job.preview_hex, "summary": job.preview_summary, "packet_count": job.packet_count}

