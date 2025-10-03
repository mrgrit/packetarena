#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata packet generator (flow-realistic, no globals)
- Input : CSV of parsed Suricata rules
- Output: Per-rule PCAPs (or single combined PCAP)
- Cache : SQLite to deduplicate
- Focus : Realistic flows (3-way + data + response + graceful close)

Usage examples:
  python suricata_packet_generator.py --csv suricata_rules_parsed.csv --dst 192.0.2.10 --src 192.168.56.10 --limit 100 --out-dir ./pcaps
  python suricata_packet_generator.py --csv suricata_rules_parsed.csv --dst 192.0.2.10 --src 192.168.56.10 --single-pcap ./all_rules.pcap --limit 200
  python suricata_packet_generator.py --csv suricata_rules_parsed.csv --dst 192.0.2.10 --src 192.168.56.10 --dry-run
"""

import argparse, json, logging, random, sqlite3, time, hashlib, os
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import pandas as pd
from scapy.all import (
    IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR, wrpcap
)

LOG = logging.getLogger("pktgen")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# =========================
# Config / Dataclass
# =========================
@dataclass
class Config:
    csv_path: Path
    dst_ip: str              # 서버/센서 IP (목적지)
    src_ip: str              # 클라이언트/소스 IP
    out_dir: Path
    cache_db: Path
    limit: int = 0
    sids: Optional[List[str]] = None
    dry_run: bool = False
    namespace: str = "templates_real_v1"
    single_pcap: Optional[Path] = None   # 모든 흐름을 하나의 pcap으로

# =========================
# Utils
# =========================
def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()

def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in (s or ""))[:180]

def stamp(pkts: List, t0: float, delta: float=0.02) -> List:
    """패킷 리스트에 증가 타임스탬프(.time) 부여"""
    t = t0
    for p in pkts:
        p.time = t
        t += delta
    return pkts

# =========================
# Cache (SQLite)
# =========================
class Cache:
    def __init__(self, db_path: Path, namespace: str):
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self.ns = namespace
        self._init()
    def _init(self):
        c=self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS pcap_cache(
            id TEXT PRIMARY KEY, ns TEXT, template TEXT, params TEXT, path TEXT, created REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sid_map(
            sid TEXT PRIMARY KEY, pcap_id TEXT, template TEXT, params TEXT, created REAL)""")
        self.conn.commit()
    def key(self, template:str, params:Dict[str,Any])->str:
        return sha1(f"{self.ns}|{template}|{json.dumps(params,sort_keys=True)}")
    def get_path(self, template:str, params:Dict[str,Any])->Optional[str]:
        k=self.key(template, params); c=self.conn.cursor()
        r=c.execute("SELECT path FROM pcap_cache WHERE id=?",(k,)).fetchone()
        return r[0] if r else None
    def put(self, template:str, params:Dict[str,Any], path:str)->str:
        k=self.key(template, params); c=self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO pcap_cache VALUES(?,?,?,?,?,?)",
                  (k,self.ns,template,json.dumps(params,sort_keys=True),path,time.time()))
        self.conn.commit(); return k
    def map_sid(self, sid:str, template:str, params:Dict[str,Any]):
        k=self.key(template, params); c=self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO sid_map VALUES(?,?,?,?,?)",
                  (sid,k,template,json.dumps(params,sort_keys=True),time.time()))
        self.conn.commit()

# =========================
# Flow Builders (REALISTIC)
# =========================
def tcp_3wh(src_ip:str, dst_ip:str, sport:int, dport:int, seq_c:int=None, seq_s:int=None)->List:
    """3-way handshake: SYN → SYN/ACK → ACK"""
    seq_c = seq_c or random.randint(10000000, 20000000)
    seq_s = seq_s or random.randint(30000000, 40000000)
    syn    = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="S",seq=seq_c,options=[('MSS',1460)])
    synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport,dport=sport,flags="SA",seq=seq_s,ack=seq_c+1,options=[('MSS',1460)])
    ack    = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="A",seq=seq_c+1,ack=seq_s+1)
    return [syn, synack, ack]

def tcp_send_cli(src_ip, dst_ip, sport, dport, seq, ack, payload:bytes):
    """클라 → 서버 데이터 + 서버 ACK"""
    p1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/Raw(payload)
    new_seq = seq + len(payload)
    p2 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport,dport=sport,flags="A",seq=ack,ack=new_seq)
    return [p1, p2], new_seq, ack

def tcp_send_srv(src_ip, dst_ip, sport, dport, seq, ack, payload:bytes):
    """서버 → 클라 데이터 + 클라 ACK"""
    p1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/Raw(payload)
    new_seq = seq + len(payload)
    p2 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport,dport=sport,flags="A",seq=ack,ack=new_seq)
    return [p1, p2], new_seq, ack

def tcp_close_gracefully(src_ip, dst_ip, sport, dport, seq_c, seq_s):
    """FIN/ACK 교환으로 정상 종료"""
    fin1 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="FA",seq=seq_c,ack=seq_s)
    ack1 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport,dport=sport,flags="A",seq=seq_s,ack=seq_c+1)
    fin2 = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport,dport=sport,flags="FA",seq=seq_s,ack=seq_c+1)
    ack2 = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="A",seq=seq_c+1,ack=seq_s+1)
    return [fin1, ack1, fin2, ack2]

def build_clienthello_with_sni(hostname: str) -> bytes:
    """
    TLS1.2 ClientHello (간소화) + SNI 확장.
    길이/필드 일관성 유지 → Suricata TLS 파서가 SNI를 추출할 수 있게 구성.
    """
    version = b'\x03\x03'
    random_bytes = b'\x11'*32
    session_id = b'\x00'
    cipher_suites = b'\x00\x02' + b'\x00\x2f'  # len + TLS_RSA_WITH_AES_128_CBC_SHA
    compression = b'\x01' + b'\x00'
    h = hostname.encode()
    sni_name = b'\x00' + len(h).to_bytes(2,'big') + h
    sni_list = len(sni_name).to_bytes(2,'big') + sni_name
    sni_ext  = b'\x00\x00' + len(sni_list).to_bytes(2,'big') + sni_list
    extensions = sni_ext
    ext_len = len(extensions).to_bytes(2,'big')
    body = version + random_bytes + session_id + cipher_suites + compression + ext_len + extensions
    hs_hdr = b'\x01' + len(body).to_bytes(3,'big')   # HandshakeType=ClientHello(1)
    record = b'\x16' + version + len(hs_hdr+body).to_bytes(2,'big') + hs_hdr + body
    return record

# =========================
# Templates (realistic flows)
# =========================
def t_http_request_flow(ctx:Dict[str,Any], req_text:str, resp_text:bytes=b"HTTP/1.1 200 OK\r\nContent-Length:0\r\n\r\n", dport:int=80)->List:
    src, dst = ctx["src"], ctx["dst"]
    sport = random.randint(20000,65000)
    # 3-way
    pkts = tcp_3wh(src, dst, sport, dport)
    cli_seq = pkts[2][TCP].seq
    srv_seq = pkts[2][TCP].ack
    # Client Request
    cpk, cli_seq, srv_seq = tcp_send_cli(src, dst, sport, dport, cli_seq, srv_seq, req_text.encode())
    pkts += cpk
    # Server Response
    spk, srv_seq, cli_seq = tcp_send_srv(dst, src, dport, sport, srv_seq, cli_seq, resp_text)
    pkts += spk
    # Close
    pkts += tcp_close_gracefully(src, dst, sport, dport, cli_seq, srv_seq)
    return stamp(pkts, time.time())

def t_tls_clienthello_flow(ctx:Dict[str,Any], sni_host:str)->List:
    src, dst = ctx["src"], ctx["dst"]; dport=443
    sport = random.randint(20000,65000)
    pkts = tcp_3wh(src, dst, sport, dport)
    cli_seq = pkts[2][TCP].seq
    srv_seq = pkts[2][TCP].ack
    hello = build_clienthello_with_sni(sni_host)
    cpk, cli_seq, srv_seq = tcp_send_cli(src, dst, sport, dport, cli_seq, srv_seq, hello)
    pkts += cpk
    # 서버는 ACK만
    pkts.append(IP(src=dst, dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=srv_seq,ack=cli_seq))
    # 종료
    pkts += tcp_close_gracefully(src, dst, sport, dport, cli_seq, srv_seq)
    return stamp(pkts, time.time())

def t_generic_marker_flow(ctx:Dict[str,Any], marker:str, dport:int=80)->List:
    src, dst = ctx["src"], ctx["dst"]
    sport = random.randint(20000,65000)
    pkts = tcp_3wh(src, dst, sport, dport)
    cli_seq = pkts[2][TCP].seq
    srv_seq = pkts[2][TCP].ack
    cpk, cli_seq, srv_seq = tcp_send_cli(src, dst, sport, dport, cli_seq, srv_seq, marker.encode())
    pkts += cpk
    pkts.append(IP(src=dst, dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=srv_seq,ack=cli_seq))
    pkts += tcp_close_gracefully(src, dst, sport, dport, cli_seq, srv_seq)
    return stamp(pkts, time.time())

def t_dns_query_flow(ctx:Dict[str,Any], qname:str, qtype:str="A")->List:
    src, dst = ctx["src"], ctx["dst"]        # dst: DNS 서버
    sport = random.randint(20000,65000)
    qid = random.randint(1,65535)
    q = DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    if qtype == "A":
        ans = DNSRR(rrname=qname, type=1, rdata="203.0.113.10")
    else:
        ans = DNSRR(rrname=qname, type=16, rdata="TESTDATA")
    a = DNS(id=qid, qr=1, aa=1, qd=DNSQR(qname=qname, qtype=qtype), an=ans)
    p1 = IP(src=src, dst=dst)/UDP(sport=sport, dport=53)/q
    p2 = IP(src=dst, dst=src)/UDP(sport=53, dport=sport)/a
    return stamp([p1, p2], time.time(), delta=0.03)

def t_syn_scan_burst(ctx:Dict[str,Any], start:int=8000, count:int=20)->List:
    src, dst = ctx["src"], ctx["dst"]
    sport = random.randint(1025,65535); seq = random.randint(1000,999999)
    pkts = [ IP(src=src, dst=dst)/TCP(sport=sport,dport=start+i,flags="S",seq=seq+i) for i in range(count) ]
    return stamp(pkts, time.time(), delta=0.004)

# =========================
# Template Mapping (rule → template)
# =========================
POTENTIALLY_DANGEROUS = {"malware","c2","exploit","smb","ssh","smtp","credentials"}

def map_rule_to_template(row: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    msg = (row.get("msg") or "").lower()
    proto = (row.get("proto") or "").lower()
    opts = (row.get("full_options") or "").lower()
    ale  = (row.get("app-layer-event") or "").lower()
    pcre = int(row.get("pcre_count") or 0)

    # 예시 휴리스틱들 (안전)
    if "http.multipart_no_filedata" in ale:
        return "http_multipart_no_filedata", {}
    if "union select" in (msg + opts):
        return "http_sqli_keyword", {"q": "UNION%20SELECT%201,2"}
    if "<script" in (msg + opts):
        return "http_xss_keyword", {"q": "%3Cscript%3Ealert(1)%3C/script%3E"}
    if "long" in msg and "uri" in msg:
        return "http_long_uri", {}
    if "tls" in (proto + msg) or "ssl" in (proto + msg):
        return "tls_like_clienthello", {}
    if "dns" in (proto + msg):
        return "dns_basic_query", {}
    if "txt" in opts:
        return "dns_txt_tunnel_like", {}
    if "scan" in msg or "syn" in msg:
        return "small_syn_scan", {}
    if pcre > 0:
        return "generic_marker", {"note": "pcre_present"}
    if "http" in (proto + msg):
        return "generic_marker", {"note": "http_uncertain"}
    return "generic_marker", {"note":"fallback"}

# =========================
# High-level Packet Generator
# =========================
class PacketGenerator:
    def __init__(self, cfg: Config, cache: Cache):
        self.cfg = cfg
        self.cache = cache

    def generate_for_rule(self, row: Dict[str, Any]) -> Tuple[List, str]:
        sid = str(row.get("sid") or "")
        tid, params = map_rule_to_template(row)
        params = dict(params); params.setdefault("sid", sid)

        ctx = {"src": self.cfg.src_ip, "dst": self.cfg.dst_ip}
        pkts: List

        # 템플릿별 플로우 생성 (리얼)
        if tid == "http_multipart_no_filedata":
            boundary = params.get("boundary") or f"----B{random.randint(1000,9999)}"
            body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n"
                    f"Content-Type: text/plain\r\n\r\n--{boundary}--\r\n")
            req = (f"POST /upload HTTP/1.1\r\nHost: {self.cfg.dst_ip}\r\n"
                   f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
                   f"Content-Length: {len(body)}\r\n\r\n{body}")
            pkts = t_http_request_flow(ctx, req)
        elif tid == "http_sqli_keyword":
            q = params.get("q","UNION%20SELECT%201,2")
            req = f"GET /search?q={q} HTTP/1.1\r\nHost: {self.cfg.dst_ip}\r\nAccept: */*\r\n\r\n"
            pkts = t_http_request_flow(ctx, req)
        elif tid == "http_xss_keyword":
            q = params.get("q","%3Cscript%3Ealert(1)%3C/script%3E")
            req = f"GET /?q={q} HTTP/1.1\r\nHost: {self.cfg.dst_ip}\r\nAccept: */*\r\n\r\n"
            pkts = t_http_request_flow(ctx, req)
        elif tid == "http_long_uri":
            long_path = "/" + ("A"*1200)
            req = f"GET {long_path} HTTP/1.1\r\nHost: {self.cfg.dst_ip}\r\n\r\n"
            pkts = t_http_request_flow(ctx, req)
        elif tid == "tls_like_clienthello":
            pkts = t_tls_clienthello_flow(ctx, "api.country.is")
        elif tid == "dns_basic_query":
            pkts = t_dns_query_flow(ctx, "example.test", "A")
        elif tid == "dns_txt_tunnel_like":
            pkts = t_dns_query_flow(ctx, "ex.test", "TXT")
        elif tid == "small_syn_scan":
            pkts = t_syn_scan_burst(ctx, 8000, 20)
        elif tid == "generic_marker":
            mk = f"SURICATA_TEST_SID_{sid}"
            pkts = t_generic_marker_flow(ctx, mk, 80)
        else:
            mk = f"SURICATA_TEST_SID_{sid}"
            pkts = t_generic_marker_flow(ctx, mk, 80)

        return pkts, tid

# =========================
# CLI
# =========================
def parse_args() -> Config:
    ap = argparse.ArgumentParser(description="Suricata PCAP generator (realistic flows)")
    ap.add_argument("--csv", required=True, help="Path to parsed Suricata rules CSV")
    ap.add_argument("--dst", required=True, help="Destination (server/sensor) IPv4")
    ap.add_argument("--src", default="192.168.56.10", help="Source (client) IPv4 [default: 192.168.56.10]")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sids", default=None, help="Comma-separated SIDs to include")
    ap.add_argument("--out-dir", default="./pcaps", help="Per-rule pcap directory")
    ap.add_argument("--cache-db", default="./packetgen_cache.db")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--single-pcap", default=None, help="Combine all flows into one PCAP (e.g., ./all_rules.pcap)")
    args = ap.parse_args()

    sids = None
    if args.sids:
        sids = [s.strip() for s in args.sids.split(",") if s.strip()]

    return Config(
        csv_path=Path(args.csv),
        dst_ip=args.dst,
        src_ip=args.src,
        out_dir=Path(args.out_dir),
        cache_db=Path(args.cache_db),
        limit=args.limit,
        sids=sids,
        dry_run=bool(args.dry_run),
        single_pcap=Path(args.single_pcap) if args.single_pcap else None
    )

def main():
    cfg = parse_args()
    df = pd.read_csv(cfg.csv_path, dtype=str).fillna("")

    if cfg.sids:
        df = df[df["sid"].astype(str).isin(cfg.sids)]
    if cfg.limit and cfg.limit > 0:
        df = df.head(cfg.limit)

    cache = Cache(cfg.cache_db, cfg.namespace)
    gen = PacketGenerator(cfg, cache)

    if cfg.dry_run:
        for _, r in df.head(50).iterrows():
            tid, _ = map_rule_to_template(r.to_dict())
            print(r.get("sid"), "->", tid)
        print(f"[DRY-RUN] Planned rules: {len(df)}")
        return

    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    combined: List = []

    for _, r in df.iterrows():
        sid = str(r.get("sid") or "")
        pkts, tid = gen.generate_for_rule(r.to_dict())

        if cfg.single_pcap:
            combined.extend(pkts)
        else:
            name = f"{safe_name(tid)}__{safe_name(sid)}__{sha1(sid+tid)[:10]}.pcap"
            out_path = str(cfg.out_dir / name)
            wrpcap(out_path, pkts)
            LOG.info("Wrote %s (packets=%d)", out_path, len(pkts))

    if cfg.single_pcap and combined:
        out = str(cfg.single_pcap if cfg.single_pcap.suffix == ".pcap"
                  else cfg.single_pcap.with_suffix(".pcap"))
        wrpcap(out, combined)
        LOG.info("Wrote combined PCAP: %s (packets=%d)", out, len(combined))

    LOG.info("Done.")

if __name__ == "__main__":
    main()
