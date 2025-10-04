#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mix ~50 Suricata rules (easy + LLM-instruction) and generate realistic multi-packet PCAPs.

Features
- Parse suricata.rules -> in-memory table
- Group similar rules -> group_id
- Difficulty split: easy vs hard
- Sample ~50 (default easy=30, hard=20; tunable)
- Easy: built-in realistic flows (TCP 3WH, server resp, FIN close / DNS Q/R / TLS ClientHello)
- Hard: ask GPT-5 for instruction JSON (structured) then render (fallback when API key absent)
- DDoS-like multi-source: --random-src N => N random *public* source IPs
- Dest /24 expansion: --dst-cclass N => within A.B.C.0/24
- Filenames contain group_id + SID + msg slug + endpoints

for use OpenAI API
export OPENAI_API_KEY="sk-여기에_당신의_API키"
export OPENAI_MODEL="gpt-5" 

Usage examples
  python mixed_50_rule_pcapgen.py --rules suricata.rules --dst 192.0.2.10 --src 192.168.56.10 --out outputs/pcaps --count 50
  python mixed_50_rule_pcapgen.py --rules suricata.rules --dst 192.0.2.10 --use-llm --single-pcap outputs/all_50.pcap
  python mixed_50_rule_pcapgen.py --rules suricata.rules --dst 203.0.113.10 --random-src 200 --dst-cclass 30 --single-pcap outputs/all_50_varied.pcap
"""

import argparse, os, re, json, random, time, hashlib, logging, ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR, wrpcap

LOG = logging.getLogger("mix50")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# =========================
# Small utils
# =========================
def sha1s(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()

def slug(s: str, n:int=40) -> str:
    s = (s or "").lower()
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'[^a-z0-9._\-]+', '_', s)
    return (s[:n] or "nomsg")

def stamp(pkts: List, t0: float, delta: float=0.02) -> List:
    t = t0
    for p in pkts:
        p.time = t
        t += delta
    return pkts

# =========================
# Parse suricata.rules (single file)
# =========================
RULE_RE = re.compile(
    r'^\s*(alert|drop|reject|pass|log)\s+[^\n]*?\([^\)]*\)\s*;?\s*$',
    re.IGNORECASE | re.MULTILINE,
)
SPLIT_OPTS_RE = re.compile(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)')

def join_continuations(text: str)->str:
    lines = text.splitlines()
    out, buf = [], []
    for ln in lines:
        if ln.rstrip().endswith("\\"):
            buf.append(ln.rstrip()[:-1] + " ")
        else:
            buf.append(ln)
            out.append("".join(buf))
            buf = []
    if buf: out.append("".join(buf))
    return "\n".join(out)

def parse_options_block(options_block: str)->Dict[str,List[str]]:
    m = {}
    if not options_block:
        return m
    parts = [p.strip() for p in SPLIT_OPTS_RE.split(options_block) if p.strip()]
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            k = k.strip(); v = v.strip()
            if len(v)>=2 and v[0]=='"' and v[-1]=='"':
                v = v[1:-1]
            m.setdefault(k, []).append(v)
        else:
            m.setdefault(p.strip(), []).append("")
    return m

def parse_rule_line(rule: str)->Optional[Dict[str,str]]:
    if "(" not in rule or ")" not in rule: return None
    header, rest = rule.split("(", 1)
    options_block = rest.rsplit(")", 1)[0].strip()
    header_norm = header.replace("<>", "->")
    header_norm = re.sub(r"\s+", " ", header_norm).strip()
    toks = header_norm.split()
    action = toks[0] if len(toks)>0 else ""
    proto  = toks[1] if len(toks)>1 else ""
    src = srcport = dst = dstport = direction = ""
    if "->" in toks:
        i = toks.index("->")
        direction = "->"
        src     = toks[2] if len(toks)>2 else ""
        srcport = toks[3] if len(toks)>3 else ""
        dst     = toks[i+1] if len(toks)>i+1 else ""
        dstport = toks[i+2] if len(toks)>i+2 else ""
    else:
        src     = toks[2] if len(toks)>2 else ""
        srcport = toks[3] if len(toks)>3 else ""
        dst     = toks[4] if len(toks)>4 else ""
        dstport = toks[5] if len(toks)>5 else ""

    opts = parse_options_block(options_block)
    def first(k: str): 
        v = opts.get(k); 
        return v[0] if v else ""
    return {
        "sid": first("sid"),
        "rev": first("rev"),
        "gid": first("gid"),
        "action": action,
        "proto": proto,
        "src": src, "src_port": srcport, "direction": direction,
        "dst": dst, "dst_port": dstport,
        "msg": first("msg"),
        "classtype": first("classtype"),
        "priority": first("priority"),
        "app-layer-event": first("app-layer-event"),
        "reference": ";".join(opts.get("reference", [])) if "reference" in opts else "",
        "metadata":  ";".join(opts.get("metadata",  [])) if "metadata"  in opts else "",
        "content_count": str(len(opts.get("content", []) or [])),
        "pcre_count":    str(len(opts.get("pcre",    []) or [])),
        "flow":      ";".join(opts.get("flow",     []) or []),
        "flowbits":  ";".join(opts.get("flowbits", []) or []),
        "full_options": options_block,
        "full_rule": rule.strip(),
    }

def parse_rules_file(path: Path)->pd.DataFrame:
    text = path.read_text(encoding="utf-8", errors="replace")
    text = join_continuations(text)
    rows = []
    for m in RULE_RE.finditer(text):
        rule = m.group(0).strip()
        if rule.lstrip().startswith("#"): 
            continue
        r = parse_rule_line(rule)
        if r: rows.append(r)
    df = pd.DataFrame(rows).fillna("")
    return df

# =========================
# Grouping (normalize -> signature -> group_id)
# =========================
ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
hex_re = re.compile(r"\b[0-9a-fA-F]{6,}\b")
num_re = re.compile(r"\b\d+\b")
domain_like_re = re.compile(r"\b([a-z0-9\-]{1,63}\.)+(com|net|org|io|co|ru|cn|kr|jp|edu|gov|uk|de|fr|xyz|top|info|biz|be|is)\b", re.I)

def norm_text(s: str) -> str:
    s = str(s).lower()
    s = ip_re.sub("<ip>", s)
    s = domain_like_re.sub("<domain>", s)
    s = hex_re.sub("<hex>", s)
    s = num_re.sub("<num>", s)
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def extract_option_keys(options: str):
    parts = re.split(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', options or "")
    keys = []; tokens=[]
    for p in parts:
        p = p.strip()
        if not p: continue
        if ":" in p:
            k, v = p.split(":", 1); k=k.strip(); v=v.strip().strip('"')
        else:
            k = p.strip(); v=""
        keys.append(k)
        if k in ("content","pcre","http.host","http.uri","dns.query","tls.sni","http.method","http.user_agent","bsize","urilen"):
            tokens.append(f"{k}={norm_text(v)[:100]}")
    # dedup keys
    seen=set(); key_core=[k for k in keys if not (k in seen or seen.add(k))]
    return key_core, sorted(set(tokens))

def group_rules(df: pd.DataFrame)->pd.DataFrame:
    sig_hashes=[]; sig_strs=[]
    for _, r in df.iterrows():
        proto = (r.get("proto","") or "").lower()
        ale   = (r.get("app-layer-event","") or "").lower()
        msg   = r.get("msg","") or ""
        opts  = r.get("full_options","") or ""
        keys, toks = extract_option_keys(opts)
        volatile={"sid","rev","gid","metadata","reference","priority"}
        key_core=[k for k in keys if k not in volatile]
        sig = "|".join([
            "proto="+proto,
            "ale="+norm_text(ale),
            "keys="+",".join(key_core),
            "tokens="+",".join(toks),
            "msg="+norm_text(msg)
        ])
        h = sha1s(sig)[:16]
        sig_hashes.append(h); sig_strs.append(sig)
    df["group_id"]=sig_hashes
    df["group_signature"]=sig_strs
    return df

# =========================
# Difficulty split (easy vs hard)
# =========================
EASY_HINT_KEYS = {
    "dns.query","http.host","http.uri","http.method","tls.sni",
    "urilen","bsize","content"
}
HARD_HINT_KEYS = {
    "pcre","byte_test","byte_extract","flowbits","distance","within",
    "dsize","isdataat","base64_decode","file.data","filemagic","luajit"
}

def split_difficulty(df: pd.DataFrame)->Tuple[pd.DataFrame,pd.DataFrame]:
    easy_idx=[]; hard_idx=[]
    for i, r in df.iterrows():
        opts = r.get("full_options","") or ""
        kset = set([p.split(":")[0].strip() for p in re.split(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', opts) if p.strip()])
        if kset & HARD_HINT_KEYS:
            hard_idx.append(i)
        elif kset & EASY_HINT_KEYS or (r.get("proto","").lower() in ("dns","http","tls")):
            easy_idx.append(i)
        else:
            hard_idx.append(i)
    return df.loc[easy_idx].copy(), df.loc[hard_idx].copy()

# =========================
# Flow builders (realistic)
# =========================
def tcp_3wh(src_ip:str, dst_ip:str, sport:int, dport:int, seq_c:int=None, seq_s:int=None)->List:
    seq_c = seq_c or random.randint(10_000_000, 20_000_000)
    seq_s = seq_s or random.randint(30_000_000, 40_000_000)
    syn    = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="S",seq=seq_c,options=[('MSS',1460)])
    synack = IP(src=dst_ip, dst=src_ip)/TCP(sport=dport,dport=sport,flags="SA",seq=seq_s,ack=seq_c+1,options=[('MSS',1460)])
    ack    = IP(src=src_ip, dst=dst_ip)/TCP(sport=sport,dport=dport,flags="A",seq=seq_c+1,ack=seq_s+1)
    return [syn,synack,ack]

def tcp_send_cli(src,dst,sport,dport,seq,ack,payload:bytes):
    p1 = IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/Raw(payload)
    new_seq = seq + len(payload)
    p2 = IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=ack,ack=new_seq)
    return [p1,p2], new_seq, ack

def tcp_send_srv(src,dst,sport,dport,seq,ack,payload:bytes):
    p1 = IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/Raw(payload)
    new_seq = seq + len(payload)
    p2 = IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=ack,ack=new_seq)
    return [p1,p2], new_seq, ack

def tcp_close(src,dst,sport,dport,seq_c,seq_s):
    fin1 = IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="FA",seq=seq_c,ack=seq_s)
    ack1 = IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=seq_s,ack=seq_c+1)
    fin2 = IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="FA",seq=seq_s,ack=seq_c+1)
    ack2 = IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="A",seq=seq_c+1,ack=seq_s+1)
    return [fin1,ack1,fin2,ack2]

def build_clienthello_with_sni(hostname: str) -> bytes:
    ver=b"\x03\x03"; rnd=b"\x11"*32; sid=b"\x00"
    ciphers=b"\x00\x02" + b"\x00\x2f"
    comp=b"\x01\x00"
    h=hostname.encode()
    sni_name=b"\x00"+len(h).to_bytes(2,'big')+h
    sni_list=len(sni_name).to_bytes(2,'big')+sni_name
    sni_ext=b"\x00\x00"+len(sni_list).to_bytes(2,'big')+sni_list
    ext_len=len(sni_ext).to_bytes(2,'big')
    body=ver+rnd+sid+ciphers+comp+ext_len+sni_ext
    hs=b"\x01"+len(body).to_bytes(3,'big')+body
    rec=b"\x16"+ver+len(hs).to_bytes(2,'big')+hs
    return rec

# =========================
# Easy templates (engine)
# =========================
def flow_http(ctx:Dict[str,Any], req:str, resp:bytes=b"HTTP/1.1 200 OK\r\nContent-Length:0\r\n\r\n", dport:int=80)->List:
    src, dst = ctx["src"], ctx["dst"]
    sport=random.randint(20000,65000)
    pk=tcp_3wh(src,dst,sport,dport)
    cli=pk[2][TCP].seq; srv=pk[2][TCP].ack
    a, cli, srv = tcp_send_cli(src,dst,sport,dport,cli,srv,req.encode()); pk+=a
    b, srv, cli = tcp_send_srv(dst,src,dport,sport,srv,cli,resp); pk+=b
    pk += tcp_close(src,dst,sport,dport,cli,srv)
    return stamp(pk, time.time())

def flow_tls_clienthello(ctx:Dict[str,Any], sni:str)->List:
    src, dst = ctx["src"], ctx["dst"]; dport=443
    sport=random.randint(20000,65000)
    pk=tcp_3wh(src,dst,sport,dport)
    cli=pk[2][TCP].seq; srv=pk[2][TCP].ack
    ch=build_clienthello_with_sni(sni)
    a, cli, srv = tcp_send_cli(src,dst,sport,dport,cli,srv,ch); pk+=a
    pk += tcp_close(src,dst,sport,dport,cli,srv)
    return stamp(pk, time.time())

def flow_dns(ctx:Dict[str,Any], qname:str, qtype:str="A")->List:
    src, dst = ctx["src"], ctx["dst"]
    sport=random.randint(20000,65000); qid=random.randint(1,65535)
    q = DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    ans = DNSRR(rrname=qname, type=(1 if qtype=="A" else 16), rdata=("203.0.113.10" if qtype=="A" else "OK"))
    a = DNS(id=qid, qr=1, aa=1, qd=DNSQR(qname=qname, qtype=qtype), an=ans)
    p1 = IP(src=src,dst=dst)/UDP(sport=sport,dport=53)/q
    p2 = IP(src=dst,dst=src)/UDP(sport=53,dport=sport)/a
    return stamp([p1,p2], time.time(), 0.03)

def flow_syn_scan(ctx:Dict[str,Any], start:int=8000, cnt:int=20)->List:
    src, dst = ctx["src"], ctx["dst"]
    sport=random.randint(1025,65535); seq=random.randint(1000,999999)
    pk=[IP(src=src,dst=dst)/TCP(sport=sport,dport=start+i,flags="S",seq=seq+i) for i in range(cnt)]
    return stamp(pk, time.time(), 0.004)

def easy_template(rule: Dict[str,str])->Tuple[str,Dict[str,Any]]:
    msg=(rule.get("msg") or "").lower()
    proto=(rule.get("proto") or "").lower()
    opts=(rule.get("full_options") or "").lower()
    if "dns" in proto or "dns.query" in opts:
        return "dns_basic", {"qname":"example.test", "qtype":"A"}
    if "tls" in proto or "tls.sni" in opts:
        return "tls_clienthello", {"sni":"example.test"}
    if "http" in proto or "http.host" in opts or "http.uri" in opts:
        return "http_get", {"req":"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}
    if "scan" in msg or "syn" in msg:
        return "syn_scan", {"start":8000, "cnt":20}
    return "http_get", {"req":"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}

def render_easy(ctx:Dict[str,Any], tmpl:str, params:Dict[str,Any])->List:
    if tmpl=="dns_basic":
        return flow_dns(ctx, params.get("qname","example.test"), params.get("qtype","A"))
    if tmpl=="tls_clienthello":
        return flow_tls_clienthello(ctx, params.get("sni","example.test"))
    if tmpl=="http_get":
        return flow_http(ctx, params.get("req","GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
    if tmpl=="syn_scan":
        return flow_syn_scan(ctx, params.get("start",8000), params.get("cnt",20))
    return flow_http(ctx, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")

# =========================
# GPT-5 Instruction (hard rules)
# =========================
OPENAI_AVAILABLE = False
try:
    from openai import OpenAI
    if os.getenv("OPENAI_API_KEY"):
        OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

INSTR_SCHEMA = {
  "type":"object",
  "properties":{
    "template_id":{"type":"string"},
    "params":{"type":"object"},
    "filename_hint":{"type":"string"},
    "rationale":{"type":"string"}
  },
  "required":["template_id","params"]
}

LLM_MODEL = os.getenv("OPENAI_MODEL", "gpt-5")

def build_prompt(rule_text:str, group_sig:str)->str:
    return f"""당신은 Suricata 룰 분석가입니다.
주어진 룰을 트리거하는 '정밀 패킷 생성 지시문(JSON)'을 작성하세요.
제약:
- 실제 익스플로잇 금지, 탐지 패턴 충족 최소 콘텐츠만.
- 리얼 플로우 전제: TCP 3-way, 서버 응답, 정상 종료. DNS는 Query/Response.
- template_id: http_request / dns_query / tls_clienthello / syn_scan 권장.
[입력 룰]
{rule_text}

[그룹 시그니처]
{group_sig}
"""

def ask_llm_for_instruction(rule_text:str, group_sig:str)->Dict[str,Any]:
    if not OPENAI_AVAILABLE:
        # Fallback heuristic
        rt = (rule_text or "").lower()
        if "dns" in rt or "dns.query" in rt:
            return {"template_id":"dns_query","params":{"qname":"hard.example.test","qtype":"A"},"filename_hint":"dns_like"}
        if "tls" in rt or "tls.sni" in rt:
            return {"template_id":"tls_clienthello","params":{"sni":"hard.example.test"},"filename_hint":"tls_sni"}
        if "http" in rt or "host" in rt or "uri" in rt:
            return {"template_id":"http_request","params":{"method":"GET","path":"/abc","headers":{"Host":"hard.example.test"},"body":""},"filename_hint":"http_get"}
        return {"template_id":"http_request","params":{"method":"GET","path":"/","headers":{"Host":"hard.example.test"},"body":""},"filename_hint":"generic_http"}
    client = OpenAI()
    resp = client.responses.create(
        model=LLM_MODEL,
        input=build_prompt(rule_text, group_sig),
        response_format={"type":"json_schema","json_schema":{"name":"PktInstr","schema":INSTR_SCHEMA,"strict":True}},
        temperature=0.2,
    )
    txt = resp.output[0].content[0].text
    try:
        return json.loads(txt)
    except Exception:
        LOG.warning("LLM returned non-JSON; using fallback.")
        return {"template_id":"http_request","params":{"method":"GET","path":"/","headers":{"Host":"hard.example.test"},"body":""},"filename_hint":"generic_http"}

def render_from_instruction(ctx:Dict[str,Any], instr:Dict[str,Any])->List:
    tid = instr.get("template_id","http_request")
    p   = instr.get("params",{}) or {}
    if tid in ("http_request","http"):
        method = p.get("method","GET")
        path   = p.get("path","/")
        headers= p.get("headers",{}) or {}
        body   = p.get("body","")
        lines=[f"{method} {path} HTTP/1.1"]
        if "Host" not in headers:
            headers["Host"]="example.test"
        for k,v in headers.items():
            lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
            req="\r\n".join(lines)+f"\r\n\r\n{body}"
        else:
            req="\r\n".join(lines)+"\r\n\r\n"
        return flow_http(ctx, req)
    if tid in ("dns_query","dns"):
        return flow_dns(ctx, p.get("qname","hard.example.test"), p.get("qtype","A"))
    if tid in ("tls_clienthello","tls"):
        return flow_tls_clienthello(ctx, p.get("sni","hard.example.test"))
    if tid in ("syn_scan","scan"):
        return flow_syn_scan(ctx, int(p.get("start",8000)), int(p.get("cnt",20)))
    return flow_http(ctx, "GET / HTTP/1.1\r\nHost: hard.example.test\r\n\r\n")

# =========================
# Endpoint expansion (DDoS-like)
# =========================
PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]

def is_public_ipv4(ip: str) -> bool:
    try:
        ip4 = ipaddress.ip_address(ip)
        if ip4.version != 4:
            return False
        for n in PRIVATE_NETS:
            if ip4 in n: return False
        return True
    except Exception:
        return False

def random_public_ipv4() -> str:
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if is_public_ipv4(ip):
            return ip

def expand_c_class(dst: str, count: int) -> List[str]:
    """A.B.C.X -> same /24 pool, include dst first, exclude .0/.255 duplicates"""
    a,b,c,_ = [int(x) for x in dst.split(".")]
    pool = [i for i in range(1,255)]
    random.shuffle(pool)
    out = [dst]
    for i in pool:
        if len(out) >= count: break
        cand = f"{a}.{b}.{c}.{i}"
        if cand != dst:
            out.append(cand)
    return out[:count]

# =========================
# Selection & naming
# =========================
def select_mix(easy_df: pd.DataFrame, hard_df: pd.DataFrame, total:int=50, easy_n:int=30)->pd.DataFrame:
    easy_n = min(easy_n, total)
    hard_n = total - easy_n
    easy_pick = easy_df.sample(n=min(easy_n, len(easy_df)), random_state=42) if len(easy_df)>0 else easy_df.head(0)
    hard_pick = hard_df.sample(n=min(hard_n, len(hard_df)), random_state=1337) if len(hard_df)>0 else hard_df.head(0)
    return pd.concat([easy_pick, hard_pick], ignore_index=True)

def pcap_name(group_id:str, sid:str, msg:str)->str:
    return f"{group_id}__SID_{sid or 'NA'}__{slug(msg, 30)}.pcap"

# =========================
# Runner
# =========================
@dataclass
class RunConfig:
    rules_path: Path
    dst: str
    src: str
    out_dir: Path
    single_pcap: Optional[Path]
    count: int
    easy_count: int
    use_llm: bool
    random_src: int
    dst_cclass: int

def run(cfg: RunConfig):
    # load & group
    df = parse_rules_file(cfg.rules_path)
    if df.empty:
        LOG.error("No rules parsed from %s", cfg.rules_path)
        return
    df = group_rules(df)

    # split & select
    easy_df, hard_df = split_difficulty(df)
    LOG.info("Parsed %d rules. Easy=%d, Hard=%d", len(df), len(easy_df), len(hard_df))
    target = select_mix(easy_df, hard_df, total=cfg.count, easy_n=cfg.easy_count)
    LOG.info("Selected %d rules (easy=%d, hard=%d)", len(target),
             sum(target.index.isin(easy_df.index)), sum(target.index.isin(hard_df.index)))

    # endpoint sets
    src_candidates = [cfg.src]
    if cfg.random_src and cfg.random_src > 0:
        src_candidates = [random_public_ipv4() for _ in range(cfg.random_src)]
        LOG.info("Random public sources: %d", len(src_candidates))

    dst_candidates = [cfg.dst]
    if cfg.dst_cclass and cfg.dst_cclass > 0:
        dst_candidates = expand_c_class(cfg.dst, cfg.dst_cclass)
        LOG.info("Expanded /24 dests: %d", len(dst_candidates))

    # ensure out dir
    all_pkts=[]
    if not cfg.single_pcap:
        cfg.out_dir.mkdir(parents=True, exist_ok=True)

    # generate
    for _, r in target.iterrows():
        sid = str(r.get("sid") or "")
        msg = r.get("msg","")
        gid = r.get("group_id","nogroup")
        rule_text = r.get("full_rule","")
        name_base = pcap_name(gid, sid, msg)
        is_easy = r.name in easy_df.index

        for s in src_candidates:
            for d in dst_candidates:
                ctx = {"src": s, "dst": d}
                name = name_base.replace(".pcap", f"__SRC_{s.replace('.','-')}__DST_{d.replace('.','-')}.pcap")
                try:
                    if is_easy:
                        tmpl, params = easy_template(r.to_dict())
                        pkts = render_easy(ctx, tmpl, params)
                    else:
                        inst = ask_llm_for_instruction(rule_text, r.get("group_signature",""))
                        pkts = render_from_instruction(ctx, inst)

                    if cfg.single_pcap:
                        all_pkts.extend(pkts)
                    else:
                        out = cfg.out_dir / name
                        wrpcap(str(out), pkts)
                        LOG.info("Wrote %s (packets=%d)", out, len(pkts))
                except Exception as e:
                    LOG.exception("Failed SID=%s (%s->%s): %s", sid, s, d, e)

    if cfg.single_pcap and all_pkts:
        outp = cfg.single_pcap if str(cfg.single_pcap).endswith(".pcap") else cfg.single_pcap.with_suffix(".pcap")
        wrpcap(str(outp), all_pkts)
        LOG.info("Wrote combined PCAP: %s (packets=%d)", outp, len(all_pkts))

def main():
    ap = argparse.ArgumentParser(description="Mix ~50 rules (easy+LLM) and generate realistic PCAPs")
    ap.add_argument("--rules", required=True, help="Path to suricata.rules")
    ap.add_argument("--dst", required=True, help="Destination/server IP (sensor)")
    ap.add_argument("--src", default="192.168.56.10", help="Source/client IP [default: 192.168.56.10]")
    ap.add_argument("--out", default="outputs/pcaps", help="Per-rule PCAP directory (disabled if --single-pcap)")
    ap.add_argument("--single-pcap", default=None, help="Write all flows into one PCAP (e.g., outputs/all_50.pcap)")
    ap.add_argument("--count", type=int, default=50, help="How many rules to test [default: 50]")
    ap.add_argument("--easy-count", type=int, default=30, help="How many from easy set [default: 30]")
    ap.add_argument("--use-llm", action="store_true", help="If set, try GPT-5; otherwise local fallback instruction")
    ap.add_argument("--random-src", type=int, default=0, help="Generate N random *public* source IPs (for DDoS-like multi-source)")
    ap.add_argument("--dst-cclass", type=int, default=0, help="Generate N destination IPs within /24 of --dst (include --dst)")
    args = ap.parse_args()

    run(RunConfig(
        rules_path=Path(args.rules),
        dst=args.dst,
        src=args.src,
        out_dir=Path(args.out),
        single_pcap=Path(args.single_pcap) if args.single_pcap else None,
        count=args.count,
        easy_count=args.easy_count,
        use_llm=bool(args.use_llm),
        random_src=int(args.random_src),
        dst_cclass=int(args.dst_cclass),
    ))

if __name__ == "__main__":
    main()

# 빠른 사용 예
# 기본 50개 (쉬움 30 + 어려움 20), per-rule PCAP
#python mixed_50_rule_pcapgen.py --rules suricata.rules --dst 192.168.100.80 --src 192.168.100.2 --out outputs/pcaps

# GPT-5 사용 (환경변수 OPENAI_API_KEY 필요)
#python mixed_50_rule_pcapgen.py --rules suricata.rules --dst 192.168.100.80 --src 192.168.100.2 --use-llm

# DDoS 느낌: 랜덤 공인 소스 200개 × 목적지 /24 30개 → 한 파일로 합치기
#python mixed_50_rule_pcapgen.py --rules suricata.rules --dst 203.0.113.10 --random-src 200 --dst-cclass 30 --single-pcap outputs/all_50_varied.pcap