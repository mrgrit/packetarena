# /opt/packetarena/backend/services/rewrite_svc.py
import os, subprocess, shlex

def tcprewrite_rewrite(in_pcap: str, out_pcap: str, src_ipmap: str|None=None,
                       dst_ipmap: str|None=None, sportmap: str|None=None,
                       dportmap: str|None=None, mtu: int|None=None):
    """
    src_ipmap/dst_ipmap 예시: "203.0.113.5:198.51.100.20"  (단일 매핑)
    포트 매핑 예시: "80:8080"
    """
    cmd = ["tcprewrite", f"--infile={in_pcap}", f"--outfile={out_pcap}"]

    if src_ipmap: cmd += ["--srcipmap="+src_ipmap]
    if dst_ipmap: cmd += ["--dstipmap="+dst_ipmap]
    if sportmap:  cmd += ["--sportmap="+sportmap]
    if dportmap:  cmd += ["--dportmap="+dportmap]
    if mtu:       cmd += [f"--mtu={int(mtu)}"]

    os.makedirs(os.path.dirname(out_pcap), exist_ok=True)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"tcprewrite failed: {proc.stdout}")
    return {"outfile": out_pcap, "output": proc.stdout}

