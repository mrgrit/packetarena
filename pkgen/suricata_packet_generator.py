#!/usr/bin/env python3
# filename: hybrid_packetgen.py
"""
Hybrid · Cache · Template packet generator for Suricata rule testing (SAFE).
- Input: suricata_rules_parsed.csv (columns: sid,msg,proto,categories,app-layer-event,pcre_count,content_count,full_options,...)
- Output: pcaps/*.pcap
- Cache: packetgen_cache.db (SQLite)
"""

import argparse, os, json, time, hashlib, logging, random, sqlite3
from typing import Dict, Any, List, Tuple, Optional
import pandas as pd

from scapy.all import IP, IPv6, TCP, UDP, Raw, DNS, DNSQR, wrpcap

LOG = logging.getLogger("packetgen")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

DB_PATH = "packetgen_cache.db"
PCAP_DIR = "pcaps"
NS = "templates_v1"

def sha1(s:str)->str: return hashlib.sha1(s.encode()).hexdigest()
def ip_for(dst:str):  return IPv6(dst=dst) if ":" in dst else IP(dst=dst)
def safe_name(s:str): return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:180]

# ---------- Templates (확장 가능) ----------
TEMPLATES = {
    "http_multipart_no_filedata": {"desc":"HTTP multipart without file data","gen":"gen_http_multipart_no_filedata"},
    "http_sqli_keyword": {"desc":"HTTP GET with SQLi-like query","gen":"gen_http_sqli_string"},
    "http_xss_keyword": {"desc":"HTTP GET with XSS-like query","gen":"gen_http_xss_string"},
    "http_long_uri": {"desc":"HTTP very long URI path","gen":"gen_http_long_uri"},
    "dns_basic_query": {"desc":"DNS A query","gen":"gen_dns_basic"},
    "dns_txt_tunnel_like": {"desc":"DNS TXT long payload (tunnel-like marker)","gen":"gen_dns_txt"},
    "tls_like_clienthello": {"desc":"TLS-like ClientHello marker","gen":"gen_tls_clienthello"},
    "small_syn_scan": {"desc":"Small SYN scan burst","gen":"gen_syn_scan"},
    "generic_marker": {"desc":"Generic TCP payload containing SID","gen":"gen_generic_marker"},
}

def gen_http_multipart_no_filedata(ctx:Dict[str,Any], p:Dict[str,Any])->List:
    dst = ctx["dst"]; sport = random.randint(1025,65535)
    boundary = p.get("boundary") or f"----B{random.randint(1000,9999)}"
    body = f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x.txt\"\r\nContent-Type: text/plain\r\n\r\n--{boundary}--\r\n"
    req = f"POST /upload HTTP/1.1\r\nHost: {dst}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\nContent-Length: {len(body)}\r\n\r\n{body}"
    return [ip_for(dst)/TCP(sport=sport,dport=80,flags="PA")/Raw(req.encode())]

def gen_http_sqli_string(ctx,p)->List:
    dst = ctx["dst"]; sport = random.randint(1025,65535)
    q = p.get("q","UNION SELECT 1,2,3")
    s = f"GET /search?q={q} HTTP/1.1\r\nHost: {dst}\r\n\r\n"
    return [ip_for(dst)/TCP(sport=sport,dport=80,flags="PA")/Raw(s.encode())]

def gen_http_xss_string(ctx,p)->List:
    dst = ctx["dst"]; sport = random.randint(1025,65535)
    q = p.get("q","<script>alert(1)</script>")
    s = f"GET /?q={q} HTTP/1.1\r\nHost: {dst}\r\n\r\n"
    return [ip_for(dst)/TCP(sport=sport,dport=80,flags="PA")/Raw(s.encode())]

def gen_http_long_uri(ctx,p)->List:
    dst=ctx["dst"]; sport=random.randint(1025,65535)
    path="/"+("A"*random.randint(800,1500))
    s=f"GET {path} HTTP/1.1\r\nHost: {dst}\r\n\r\n"
    return [ip_for(dst)/TCP(sport=sport,dport=80,flags="PA")/Raw(s.encode())]

def gen_dns_basic(ctx,p)->List:
    dst=ctx["dst"]; sport=random.randint(1025,65535)
    qname = p.get("qname","test.local")
    return [ip_for(dst)/UDP(sport=sport,dport=53)/DNS(rd=1,qd=DNSQR(qname=qname,qtype="A"))]

def gen_dns_txt(ctx,p)->List:
    from scapy.layers.dns import DNSRR
    dst=ctx["dst"]; sport=random.randint(1025,65535)
    txt = p.get("txt","DATA"*50)
    return [ip_for(dst)/UDP(sport=sport,dport=53)/DNS(rd=1,qd=DNSQR(qname="ex.test",qtype="TXT"),an=DNSRR(rrname="ex.test",type=16,rdata=txt))]

def gen_tls_clienthello(ctx,p)->List:
    dst=ctx["dst"]; sport=random.randint(1025,65535)
    payload=b"\x16\x03\x01\x00\x31CLIENT_HELLO_TEST"
    return [ip_for(dst)/TCP(sport=sport,dport=443,flags="PA")/Raw(payload)]

def gen_syn_scan(ctx,p)->List:
    dst=ctx["dst"]; start=int(p.get("start",8000)); count=int(p.get("count",20))
    ip=ip_for(dst); sport=random.randint(1025,65535); seq=random.randint(1000,999999)
    return [ip/TCP(sport=sport,dport=start+i,flags="S",seq=seq+i) for i in range(count)]

def gen_generic_marker(ctx,p)->List:
    dst=ctx["dst"]; sport=random.randint(1025,65535)
    sid=p.get("sid","NA")
    s=f"SURICATA_TEST_SID_{sid}".encode()
    return [ip_for(dst)/TCP(sport=sport,dport=80,flags="PA")/Raw(s)]

GEN = {
    "gen_http_multipart_no_filedata": gen_http_multipart_no_filedata,
    "gen_http_sqli_string": gen_http_sqli_string,
    "gen_http_xss_string": gen_http_xss_string,
    "gen_http_long_uri": gen_http_long_uri,
    "gen_dns_basic": gen_dns_basic,
    "gen_dns_txt": gen_dns_txt,
    "gen_tls_clienthello": gen_tls_clienthello,
    "gen_syn_scan": gen_syn_scan,
    "gen_generic_marker": gen_generic_marker,
}

# ---------- Cache ----------
class Cache:
    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init()
    def _init(self):
        c=self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS pcap_cache(
            id TEXT PRIMARY KEY, ns TEXT, template TEXT, params TEXT, path TEXT, created REAL)""")
        c.execute("""CREATE TABLE IF NOT EXISTS sid_map(
            sid TEXT PRIMARY KEY, pcap_id TEXT, template TEXT, params TEXT, created REAL)""")
        self.conn.commit()
    def key(self, t, params)->str:
        return sha1(f"{NS}|{t}|{json.dumps(params,sort_keys=True)}")
    def get(self, t, params)->Optional[str]:
        k=self.key(t,params); c=self.conn.cursor()
        r=c.execute("SELECT path FROM pcap_cache WHERE id=?",(k,)).fetchone()
        return r[0] if r else None
    def put(self, t, params, path):
        k=self.key(t,params); c=self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO pcap_cache VALUES(?,?,?,?,?,?)",
                  (k,NS,t,json.dumps(params),path,time.time()))
        self.conn.commit(); return k
    def map_sid(self, sid, k, t, params):
        c=self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO sid_map VALUES(?,?,?,?,?)",
                  (str(sid),k,t,json.dumps(params),time.time()))
        self.conn.commit()

# ---------- Heuristic mapping (rule -> template) ----------
POTENTIALLY_DANGEROUS = {"malware","c2","exploit","smb","ssh","smtp","credentials"}

def map_rule(row:Dict[str,Any])->Tuple[str,Dict[str,Any]]:
    msg=(row.get("msg") or "").lower()
    ale=(row.get("app-layer-event") or "").lower()
    cats=(row.get("categories") or "").lower()
    proto=(row.get("proto") or "").lower()
    opts=(row.get("full_options") or "").lower()
    pcre=int(row.get("pcre_count") or 0)

    if "http.multipart_no_filedata" in ale: return "http_multipart_no_filedata", {}
    if "union select" in (msg+opts):       return "http_sqli_keyword", {"q":"UNION%20SELECT%201,2"}
    if "<script" in (msg+opts):            return "http_xss_keyword", {"q":"%3Cscript%3Ealert(1)%3C/script%3E"}
    if "long" in msg and "uri" in msg:     return "http_long_uri", {}
    if "dns" in (proto+cats+msg):          return "dns_basic_query", {}
    if "txt" in (msg+opts):                return "dns_txt_tunnel_like", {}
    if "tls" in (proto+cats+msg) or "ssl" in (proto+cats+msg): return "tls_like_clienthello", {}
    if "scan" in msg or "syn" in msg:      return "small_syn_scan", {}
    for bad in POTENTIALLY_DANGEROUS:
        if bad in cats: return "generic_marker", {"note":"safe_marker"}
    if pcre>0: return "generic_marker", {"note":"pcre_present"}
    if "http" in (proto+cats+msg): return "generic_marker", {"note":"http_uncertain"}
    return "generic_marker", {"note":"fallback"}

def instantiate(template_id:str, params:Dict[str,Any], ctx:Dict[str,Any])->List:
    meta=TEMPLATES.get(template_id); assert meta, f"Unknown template {template_id}"
    fn=GEN[meta["gen"]]; return fn(ctx, params)

def generate_for_rule(row:Dict[str,Any], ctx:Dict[str,Any], cache:Cache)->Tuple[str,str]:
    sid=str(row.get("sid") or "")
    t, params = map_rule(row)
    params=dict(params); params.setdefault("sid", sid)

    cached=cache.get(t, params)
    if cached:
        cache.map_sid(sid, cache.key(t,params), t, params)
        LOG.info("Cache hit: SID %s -> %s", sid, cached); return cached, t

    pkts=instantiate(t, params, ctx)
    os.makedirs(PCAP_DIR, exist_ok=True)
    name=f"{safe_name(t)}__{safe_name(sid)}__{sha1(json.dumps(params,sort_keys=True))[:10]}.pcap"
    out=os.path.join(PCAP_DIR,name)
    wrpcap(out, pkts)
    k=cache.put(t, params, out)
    cache.map_sid(sid, k, t, params)
    LOG.info("Generated: SID %s -> %s (%d pkts)", sid, out, len(pkts))
    return out, t

def main():
    ap=argparse.ArgumentParser(description="Hybrid·Cache·Template Suricata PCAP generator")
    ap.add_argument("--csv", required=True)
    ap.add_argument("--dst", required=True, help="Destination IP (sensor)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sids", default=None, help="Comma-separated whitelist")
    ap.add_argument("--out-dir", default=PCAP_DIR)
    ap.add_argument("--dry-run", action="store_true")
    args=ap.parse_args()

    global PCAP_DIR; PCAP_DIR=args.out_dir
    df=pd.read_csv(args.csv, dtype=str)
    if args.sids:
        ws=set(x.strip() for x in args.sids.split(",") if x.strip())
        df=df[df["sid"].astype(str).isin(ws)]
    if args.limit>0: df=df.head(args.limit)

    cache=Cache(DB_PATH); ctx={"dst": args.dst}
    if args.dry_run:
        for _,r in df.head(50).iterrows():
            t,_p=map_rule(r.to_dict()); print(r.get("sid"), t)
        print(f"Planned: {len(df)} rules"); return

    count=0
    for _,r in df.iterrows():
        generate_for_rule(r.to_dict(), ctx, cache); count+=1
    LOG.info("Done. Generated or reused for %d rules. Out: %s", count, PCAP_DIR)

if __name__=="__main__":
    main()
