# /opt/packetarena/backend/services/remote_capture.py
import os, time, uuid, paramiko
from typing import Optional

def ssh_run(host, user, keyfile, cmd, timeout=None):
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    cli.connect(hostname=host, username=user, key_filename=keyfile, timeout=10)
    try:
        _, stdout, stderr = cli.exec_command(cmd, timeout=timeout)
        out, err = stdout.read().decode(), stderr.read().decode()
        code = stdout.channel.recv_exit_status()
        return code, out, err
    finally:
        cli.close()

def sftp_fetch(host, user, keyfile, remote_path, local_path):
    os.makedirs(os.path.dirname(local_path), exist_ok=True)
    t = paramiko.Transport((host, 22))
    t.connect(username=user, key_filename=keyfile)
    try:
        sftp = paramiko.SFTPClient.from_transport(t)
        sftp.get(remote_path, local_path)
    finally:
        t.close()

def capture_once(*, host: str, user: str, keyfile: str, iface: str,
                 duration_sec: int = 20, remote_path: str = "/tmp/packetarena_cap.pcap",
                 sudo: bool = True, local_store_dir: str = "/opt/packetarena/captures") -> dict:
    """
    duration만큼 tcpdump 실행 후 종료 → 파일을 로컬로 가져와 저장.
    """
    cap_id = str(uuid.uuid4())
    local_path = os.path.join(local_store_dir, f"{cap_id}.pcap")
    # -U: packet-buffered, -n: no name resolve, -w: write file
    tcpdump_cmd = f"timeout {duration_sec}s tcpdump -i {iface} -U -n -w {remote_path}"
    if sudo:
        tcpdump_cmd = "sudo -n " + tcpdump_cmd

    code, out, err = ssh_run(host, user, keyfile, tcpdump_cmd, timeout=duration_sec + 5)
    if code not in (0, 124):
        # 124는 timeout(정상 종료)
        raise RuntimeError(f"tcpdump failed (code={code})\nstdout:{out}\nstderr:{err}")

    # 파일 회수
    sftp_fetch(host, user, keyfile, remote_path, local_path)
    # 원격 파일 정리(실패해도 무시)
    try:
        ssh_run(host, user, keyfile, f"rm -f {remote_path}")
    except Exception:
        pass

    return {"capture_id": cap_id, "local_path": local_path}

