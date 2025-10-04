from fastapi import APIRouter, HTTPException, Query, Depends
from sqlalchemy.orm import Session
from settings import settings
from deps import get_db
from services.suri_indexer import bulk_index_events
import paramiko

router = APIRouter(prefix="", tags=["logs-index"])

def ssh_tail_n(host: str, user: str, keyfile: str, path: str, n: int = 10000, sudo: bool = False):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(hostname=host, username=user, key_filename=keyfile, timeout=10)
    try:
        cmd = f"tail -n {n} {path}"
        if sudo: cmd = "sudo -n " + cmd
        _, stdout, _ = cli.exec_command(cmd, timeout=30)
        for line in stdout:
            yield line
    finally:
        cli.close()

@router.post("/logs/index/remote")
def index_remote(
    host: str = Query(...),
    n: int = Query(10000, ge=1, le=200000),
    sudo: bool = Query(False),
    db: Session = Depends(get_db)
):
    lines = ssh_tail_n(host, settings.SSH_USER, settings.SSH_KEYFILE, settings.REMOTE_EVE_PATH, n=n, sudo=sudo)
    try:
        count = bulk_index_events(db, lines)
        return {"indexed": count}
    except Exception as e:
        raise HTTPException(500, f"index failed: {e}")
