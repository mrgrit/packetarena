#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata packet generator (refactored, no globals)
- Input: CSV with parsed Suricata rules
- Output: PCAPs in out_dir
- Cache: SQLite file (optional) to deduplicate generation

Usage:
  python suricata_packet_generator.py --csv suricata_rules_parsed.csv --dst 192.0.2.10 --limit 100 --out-dir ./pcaps
  python suricata_packet_generator.py --csv suricata_rules_parsed.csv --dst 192.0.2.10 --dry-run
"""

import argparse
import json
import logging
import os
import random
import sqlite3
import time
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import pandas as pd
from scapy.all import IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, wrpcap

# ------------------------------ logging ------------------------------
LOG = logging.getLogger("pktgen")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ------------------------------ config ------------------------------
@dataclass
class Config:
    csv_path: Path
    dst_ip: str
    out_dir: Path
    cache_db: Path
    limit: int = 0
    sids: Optional[List[str]] = None
    dry_run: bool = False
    namespace: str = "templates_v1"


# ------------------------------ utils ------------------------------
def sha1(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()

def ip_for(dst: str):
    return IPv6(dst=dst) if ":" in dst else IP(dst=dst)

def safe_name(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in (s or ""))[:180]


# ------------------------------ cache ------------------------------
class Cache:
    def __init__(self, db_path: Path, namespace: str):
        self.db_path = db_path
        self.ns = namespace
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS pcap_cache(
            id TEXT PRIMARY KEY, ns TEXT, template TEXT, params TEXT, path TEXT, created REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sid_map(
            sid TEXT PRIMARY KEY, pcap_id TEXT, template TEXT, params TEXT, created REAL)""")
        self.conn.commit()

    def key(self, template: str, params: Dict[str, Any]) -> str:
        return sha1(f"{self.ns}|{template}|{json.dumps(params, sort_keys=True)}")

    def get_path(self, template: str, params: Dict[str, Any]) -> Optional[str]:
        k = self.key(template, params)
        c = self.conn.cursor()
        r = c.execute("SELECT path FROM pcap_cache WHERE id=?", (k,)).fetchone()
        return r[0] if r else None

    def put(self, template: str, params: Dict[str, Any], path: str) -> str:
        k = self.key(template, params)
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO pcap_cache VALUES(?,?,?,?,?,?)",
                  (k, self.ns, template, json.dumps(params, sort_keys=True), path, time.time()))
        self.conn.commit()
        return k

    def map_sid(self, sid: str, template: str, params: Dict[str, Any]):
        k = self.key(template, params)
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO sid_map VALUES(?,?,?,?,?)",
                  (sid, k, template, json.dumps(params, sort_keys=True), time.time()))
        self.conn.commit()


# ------------------------------ templates ------------------------------
class TemplateRegistry:
    """
    Registry: template_id -> generator function
    Each generator returns a List[Packet]
    """
    def __init__(self):
        self.templates: Dict[str, Dict[str, Any]] = {}
        self.generators: Dict[str, Any] = {}
        self._register_defaults()

    def _register(self, template_id: str, desc: str, fn):
        self.templates[template_id] = {"desc": desc, "gen": fn}
        self.generators[template_id] = fn

    def _register_defaults(self):
        self._register("http_multipart_no_filedata", "HTTP multipart without file data", gen_http_multipart_no_filedata)
        self._register("http_sqli_keyword", "HTTP GET with SQLi-like query", gen_http_sqli_string)
        self._register("http_xss_keyword", "HTTP GET with XSS-like query", gen_http_xss_string)
        self._register("http_long_uri", "HTTP very long URI path", gen_http_long_uri)
        self._register("dns_basic_query", "DNS A query", gen_dns_basic)
        self._register("dns_txt_tunnel_like", "DNS TXT long payload (tunnel-like)", gen_dns_txt)
        self._register("tls_like_clienthello", "TLS-like ClientHello marker", gen_tls_clienthello)
        self._register("small_syn_scan", "Small SYN scan burst", gen_syn_scan)
        self._register("generic_marker", "Generic TCP payload containing SID", gen_generic_marker)

    def list_ids(self) -> List[str]:
        return list(self.templates.keys())

    def generate(self, template_id: str, ctx: Dict[str, Any], params: Dict[str, Any]) -> List:
        if template_id not in self.generators:
            raise KeyError(f"Unknown template: {template_id}")
        return self.generators[template_id](ctx, params)


# ------------------------------ packet generators ------------------------------
def gen_http_multipart_no_filedata(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    boundary = p.get("boundary") or f"----B{random.randint(1000, 9999)}"
    body = (
        f"--{boundary}\r\n"
        f"Content-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\n"
        f"Content-Type: text/plain\r\n\r\n"
        f"--{boundary}--\r\n"
    )
    req = (
        f"POST /upload HTTP/1.1\r\nHost: {dst}\r\n"
        f"Content-Type: multipart/form-data; boundary={boundary}\r\n"
        f"Content-Length: {len(body)}\r\n\r\n{body}"
    )
    return [ip_for(dst)/TCP(sport=sport, dport=80, flags="PA")/Raw(req.encode())]

def gen_http_sqli_string(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    q = p.get("q", "UNION SELECT 1,2,3")
    s = f"GET /search?q={q} HTTP/1.1\r\nHost: {dst}\r\n\r\n"
    return [ip_for(dst)/TCP(sport=sport, dport=80, flags="PA")/Raw(s.encode())]

def gen_http_xss_string(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    q = p.get("q", "<script>alert(1)</script>")
    s = f"GET /?q={q} HTTP/1.1\r\nHost: {dst}\r\n\r\n"
    return [ip_for(dst)/TCP(sport=sport, dport=80, flags="PA")/Raw(s.encode())]

def gen_http_long_uri(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    path = "/" + ("A" * random.randint(800, 1500))
    s = f"GET {path} HTTP/1.1\r\nHost: {dst}\r\n\r\n"
    return [ip_for(dst)/TCP(sport=sport, dport=80, flags="PA")/Raw(s.encode())]

def gen_dns_basic(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    qname = p.get("qname", "test.local")
    return [ip_for(dst)/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))]

def gen_dns_txt(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    from scapy.layers.dns import DNSRR
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    txt = p.get("txt", "DATA" * 50)
    return [ip_for(dst)/UDP(sport=sport, dport=53)/DNS(rd=1, qd=DNSQR(qname="ex.test", qtype="TXT"),
                                                        an=DNSRR(rrname="ex.test", type=16, rdata=txt))]

def gen_tls_clienthello(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    # Minimalistic TLS ClientHello marker (for SNI-like rules, not a full handshake)
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    payload = b"\x16\x03\x01\x00\x31CLIENT_HELLO_TEST"
    return [ip_for(dst)/TCP(sport=sport, dport=443, flags="PA")/Raw(payload)]

def gen_syn_scan(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; start = int(p.get("start", 8000)); count = int(p.get("count", 20))
    ip = ip_for(dst); sport = random.randint(1025, 65535); seq = random.randint(1000, 999999)
    return [ip/TCP(sport=sport, dport=start+i, flags="S", seq=seq+i) for i in range(count)]

def gen_generic_marker(ctx: Dict[str, Any], p: Dict[str, Any]) -> List:
    dst = ctx["dst"]; sport = random.randint(1025, 65535)
    sid = p.get("sid", "NA")
    s = f"SURICATA_TEST_SID_{sid}".encode()
    return [ip_for(dst)/TCP(sport=sport, dport=80, flags="PA")/Raw(s)]


# ------------------------------ rule mapping ------------------------------
POTENTIALLY_DANGEROUS = {"malware","c2","exploit","smb","ssh","smtp","credentials"}

def map_rule_to_template(row: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """Heuristic mapping (safe). Expand later."""
    msg = (row.get("msg") or "").lower()
    ale = (row.get("app-layer-event") or "").lower()
    cats = (row.get("categories") or "").lower()
    proto = (row.get("proto") or "").lower()
    opts = (row.get("full_options") or "").lower()
    pcre = int(row.get("pcre_count") or 0)

    if "http.multipart_no_filedata" in ale:
        return "http_multipart_no_filedata", {}
    if "union select" in (msg + opts):
        return "http_sqli_keyword", {"q": "UNION%20SELECT%201,2"}
    if "<script" in (msg + opts):
        return "http_xss_keyword", {"q": "%3Cscript%3Ealert(1)%3C/script%3E"}
    if "long" in msg and "uri" in msg:
        return "http_long_uri", {}
    if "dns" in (proto + cats + msg):
        return "dns_basic_query", {}
    if "txt" in (msg + opts):
        return "dns_txt_tunnel_like", {}
    if "tls" in (proto + cats + msg) or "ssl" in (proto + cats + msg):
        return "tls_like_clienthello", {}
    if "scan" in msg or "syn" in msg:
        return "small_syn_scan", {}

    for kw in POTENTIALLY_DANGEROUS:
        if kw in cats:
            return "generic_marker", {"note": "safe_marker"}
    if pcre > 0:
        return "generic_marker", {"note": "pcre_present"}
    if "http" in (proto + cats + msg):
        return "generic_marker", {"note": "http_uncertain"}

    return "generic_marker", {"note": "fallback"}


# ------------------------------ generator (high-level) ------------------------------
class PacketGenerator:
    def __init__(self, config: Config, registry: TemplateRegistry, cache: Cache):
        self.cfg = config
        self.reg = registry
        self.cache = cache

    def _instantiate(self, template_id: str, params: Dict[str, Any], ctx: Dict[str, Any]) -> List:
        return self.reg.generate(template_id, ctx, params)

    def generate_for_rule(self, row: Dict[str, Any]) -> Tuple[str, str]:
        sid = str(row.get("sid") or "")
        template_id, params = map_rule_to_template(row)
        params = dict(params)
        params.setdefault("sid", sid)

        cached_path = self.cache.get_path(template_id, params)
        if cached_path:
            self.cache.map_sid(sid, template_id, params)
            LOG.info("Cache hit: SID %s -> %s", sid, cached_path)
            return cached_path, template_id

        packets = self._instantiate(template_id, params, {"dst": self.cfg.dst_ip})
        self.cfg.out_dir.mkdir(parents=True, exist_ok=True)
        out_name = f"{safe_name(template_id)}__{safe_name(sid)}__{sha1(json.dumps(params, sort_keys=True))[:10]}.pcap"
        out_path = str(self.cfg.out_dir / out_name)
        wrpcap(out_path, packets)
        self.cache.put(template_id, params, out_path)
        self.cache.map_sid(sid, template_id, params)
        LOG.info("Generated: SID %s -> %s (%d pkts)", sid, out_path, len(packets))
        return out_path, template_id


# ------------------------------ CLI ------------------------------
def parse_args() -> Config:
    ap = argparse.ArgumentParser(description="Suricata PCAP generator (refactored, no globals)")
    ap.add_argument("--csv", required=True, help="Path to parsed Suricata rules CSV")
    ap.add_argument("--dst", required=True, help="Destination IP (sensor)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sids", default=None, help="Comma-separated whitelist of SIDs")
    ap.add_argument("--out-dir", default="./pcaps")
    ap.add_argument("--cache-db", default="./packetgen_cache.db")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    sids = None
    if args.sids:
        sids = [s.strip() for s in args.sids.split(",") if s.strip()]

    cfg = Config(
        csv_path=Path(args.csv),
        dst_ip=args.dst,
        out_dir=Path(args.out_dir),
        cache_db=Path(args.cache_db),
        limit=args.limit,
        sids=sids,
        dry_run=bool(args.dry_run),
    )
    return cfg


def main():
    cfg = parse_args()
    df = pd.read_csv(cfg.csv_path, dtype=str).fillna("")

    if cfg.sids:
        df = df[df["sid"].astype(str).isin(cfg.sids)]
    if cfg.limit and cfg.limit > 0:
        df = df.head(cfg.limit)

    reg = TemplateRegistry()
    cache = Cache(cfg.cache_db, cfg.namespace)
    gen = PacketGenerator(cfg, reg, cache)

    if cfg.dry_run:
        for _, r in df.head(50).iterrows():
            tid, _ = map_rule_to_template(r.to_dict())
            print(r.get("sid"), "->", tid)
        print(f"[DRY-RUN] Planned rules: {len(df)}")
        return

    count = 0
    for _, r in df.iterrows():
        gen.generate_for_rule(r.to_dict())
        count += 1

    LOG.info("Done. Generated/reused for %d rules. Output: %s", count, cfg.out_dir)


if __name__ == "__main__":
    main()
