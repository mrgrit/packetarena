#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkgen_by_suricata_rules_pilot.py
(mini→autofix→mini-재시도→fallback 승격 + 입력축약 + LLM 캐시 + 설명/계획 로그)
+ 파일명: __by_<model>__v<rev>__L<length>
+ cache hit 여도 현재 SID 기준 .qna 로그 생성
+ --max-pkts 로 패킷 수 상한(0=무제한)
+ .qna에 PACKET_COUNT, FILE, RULE_REV/GID, LLM_STATUS 기록

python3 pkgen_by_suricata_rules_pilot.py \
  --parsed suricata_rules_parsed.csv \
  --dst 192.168.100.80 --src 111.111.111.111 \
  --use-llm --count 50 --out outputs/pcaps --max-pkts 0

필수: pip install -U scapy pandas openai
환경: OPENAI_API_KEY, (선택) OPENAI_MODEL_PRIMARY=gpt-5-mini, OPENAI_MODEL_FALLBACK=gpt-5
"""

import argparse, os, re, json, random, time, hashlib, logging, ipaddress, sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR, wrpcap

LOG = logging.getLogger("pkgen")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# ------------ 글로벌 옵션 ------------
ALLOW_LENIENT = True  # 길이 경고 등은 통과시키는 관용 모드
RETRY_FIXABLE = {"dns_missing_qname","http_missing_method","tls_missing_sni","scan_missing_params"}

# ============================== utils ==============================
def sha1s(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()

def slug(s: str, n:int=40) -> str:
    s = (s or "").lower()
    s = re.sub(r'\s+', ' ', s).strip()
    s = re.sub(r'[^a-z0-9._\\-]+', '_', s)
    return (s[:n] or "nomsg")

def stamp(pkts: List, t0: float, delta: float=0.02) -> List:
    t = t0
    for p in pkts:
        p.time = t
        t += delta
    return pkts

# ======================== parse suricata.rules ======================
RULE_RE = re.compile(r'^\s*(alert|drop|reject|pass|log)\s+[^\n]*?\([^\)]*\)\s*;?\s*$', re.I | re.M)
SPLIT_OPTS_RE = re.compile(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)')

def join_continuations(text: str)->str:
    lines = text.splitlines()
    out, buf = [], []
    for ln in lines:
        if ln.rstrip().endswith("\\"):
            buf.append(ln.rstrip()[:-1] + " ")
        else:
            buf.append(ln)
            out.append("".join(buf)); buf = []
    if buf: out.append("".join(buf))
    return "\n".join(out)

def parse_options_block(options_block: str)->Dict[str,List[str]]:
    m = {}
    if not options_block: return m
    parts = [p.strip() for p in SPLIT_OPTS_RE.split(options_block) if p.strip()]
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            k = k.strip(); v = v.strip()
            if len(v)>=2 and v[0]=='"' and v[-1]=='"': v = v[1:-1]
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
        direction = "->"; src = toks[2] if len(toks)>2 else ""; srcport = toks[3] if len(toks)>3 else ""
        dst = toks[i+1] if len(toks)>i+1 else ""; dstport = toks[i+2] if len(toks)>i+2 else ""
    else:
        src = toks[2] if len(toks)>2 else ""; srcport = toks[3] if len(toks)>3 else ""
        dst = toks[4] if len(toks)>4 else ""; dstport = toks[5] if len(toks)>5 else ""
    opts = parse_options_block(options_block)
    def first(k: str): v = opts.get(k); return v[0] if v else ""
    return {
        "sid": first("sid"), "rev": first("rev"), "gid": first("gid"),
        "action": action, "proto": proto,
        "src": src, "src_port": srcport, "direction": direction,
        "dst": dst, "dst_port": dstport,
        "msg": first("msg"), "classtype": first("classtype"),
        "priority": first("priority"), "app-layer-event": first("app-layer-event"),
        "reference": ";".join(opts.get("reference", [])) if "reference" in opts else "",
        "metadata":  ";".join(opts.get("metadata",  [])) if "metadata"  in opts else "",
        "content_count": str(len(opts.get("content", []) or [])),
        "pcre_count":    str(len(opts.get("pcre",    []) or [])),
        "flow":      ";".join(opts.get("flow",     []) or []),
        "flowbits":  ";".join(opts.get("flowbits", []) or []),
        "full_options": options_block, "full_rule": rule.strip(),
    }

def parse_rules_file(path: Path)->pd.DataFrame:
    text = join_continuations(path.read_text(encoding="utf-8", errors="replace"))
    rows = []
    for m in RULE_RE.finditer(text):
        rule = m.group(0).strip()
        if rule.lstrip().startswith("#"): continue
        r = parse_rule_line(rule)
        if r: rows.append(r)
    return pd.DataFrame(rows).fillna("")

# ============================ grouping =============================
ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
hex_re = re.compile(r"\b[0-9a-fA-F]{6,}\b")
num_re = re.compile(r"\b\d+\b")
domain_like_re = re.compile(r"\b([a-z0-9\-]{1,63}\.)+(com|net|org|io|co|ru|cn|kr|jp|edu|gov|uk|de|fr|xyz|top|info|biz|be|is)\b", re.I)

def norm_text(s: str) -> str:
    s = str(s).lower()
    s = ip_re.sub("<ip>", s); s = domain_like_re.sub("<domain>", s)
    s = hex_re.sub("<hex>", s); s = num_re.sub("<num>", s)
    return re.sub(r'\s+', ' ', s).strip()

def extract_option_keys(options: str):
    parts = re.split(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', options or "")
    keys, tokens = [], []
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
    seen=set(); key_core=[k for k in keys if not (k in seen or seen.add(k))]
    return key_core, sorted(set(tokens))

def group_rules(df: pd.DataFrame)->pd.DataFrame:
    sig_hashes=[]; sig_strs=[]
    for _, r in df.iterrows():
        proto=(r.get("proto","") or "").lower()
        ale=(r.get("app-layer-event","") or "").lower()
        msg=r.get("msg","") or ""; opts=r.get("full_options","") or ""
        keys,toks=extract_option_keys(opts)
        volatile={"sid","rev","gid","metadata","reference","priority"}
        key_core=[k for k in keys if k not in volatile]
        sig="|".join(["proto="+proto,"ale="+norm_text(ale),"keys="+",".join(key_core),
                      "tokens="+",".join(toks),"msg="+norm_text(msg)])
        h=sha1s(sig)[:16]; sig_hashes.append(h); sig_strs.append(sig)
    df["group_id"]=sig_hashes; df["group_signature"]=sig_strs
    return df

# ======================== difficulty split =========================
EASY_HINT_KEYS={"dns.query","http.host","http.uri","http.method","tls.sni","urilen","bsize","content"}
HARD_HINT_KEYS={"pcre","byte_test","byte_extract","flowbits","distance","within","dsize","isdataat","base64_decode","file.data","filemagic","luajit"}

def split_difficulty(df: pd.DataFrame)->Tuple[pd.DataFrame,pd.DataFrame]:
    easy_idx=[]; hard_idx=[]
    for i, r in df.iterrows():
        opts=r.get("full_options","") or ""
        kset=set([p.split(":")[0].strip() for p in re.split(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)', opts) if p.strip()])
        if kset & HARD_HINT_KEYS: hard_idx.append(i)
        elif kset & EASY_HINT_KEYS or (r.get("proto","").lower() in ("dns","http","tls")): easy_idx.append(i)
        else: hard_idx.append(i)
    return df.loc[easy_idx].copy(), df.loc[hard_idx].copy()

# ===================== realistic flow builders =====================
def tcp_3wh(src_ip:str, dst_ip:str, sport:int, dport:int, seq_c:int=None, seq_s:int=None)->List:
    seq_c = seq_c or random.randint(10_000_000, 20_000_000)
    seq_s = seq_s or random.randint(30_000_000, 40_000_000)
    syn=IP(src=src_ip,dst=dst_ip)/TCP(sport=sport,dport=dport,flags="S",seq=seq_c,options=[('MSS',1460)])
    synack=IP(src=dst_ip,dst=src_ip)/TCP(sport=dport,dport=sport,flags="SA",seq=seq_s,ack=seq_c+1,options=[('MSS',1460)])
    ack=IP(src=src_ip,dst=dst_ip)/TCP(sport=sport,dport=dport,flags="A",seq=seq_c+1,ack=seq_s+1)
    return [syn,synack,ack]

def tcp_send_cli(src,dst,sport,dport,seq,ack,payload:bytes):
    p1=IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/Raw(payload)
    new_seq = seq + len(payload)
    p2=IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=ack,ack=new_seq)
    return [p1,p2], new_seq, ack

def tcp_send_srv(src,dst,sport,dport,seq,ack,payload:bytes):
    p1=IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="PA",seq=seq,ack=ack)/Raw(payload)
    new_seq = seq + len(payload)
    p2=IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=ack,ack=new_seq)
    return [p1,p2], new_seq, ack

def tcp_close(src,dst,sport,dport,seq_c,seq_s):
    fin1=IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="FA",seq=seq_c,ack=seq_s)
    ack1=IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="A",seq=seq_s,ack=seq_c+1)
    fin2=IP(src=dst,dst=src)/TCP(sport=dport,dport=sport,flags="FA",seq=seq_s,ack=seq_c+1)
    ack2=IP(src=src,dst=dst)/TCP(sport=sport,dport=dport,flags="A",seq=seq_c+1,ack=seq_s+1)
    return [fin1,ack1,fin2,ack2]

def build_clienthello_with_sni(hostname: str) -> bytes:
    ver=b"\x03\x03"; rnd=b"\x11"*32; sid=b"\x00"
    ciphers=b"\x00\x02"+b"\x00\x2f"; comp=b"\x01\x00"
    h=hostname.encode(); sni_name=b"\x00"+len(h).to_bytes(2,'big')+h
    sni_list=len(sni_name).to_bytes(2,'big')+sni_name; sni_ext=b"\x00\x00"+len(sni_list).to_bytes(2,'big')+sni_list
    ext_len=len(sni_ext).to_bytes(2,'big')
    body=ver+rnd+sid+ciphers+comp+ext_len+sni_ext; hs=b"\x01"+len(body).to_bytes(3,'big')+body
    return b"\x16"+ver+len(hs).to_bytes(2,'big')+hs

def flow_http(ctx:Dict[str,Any], req:str, resp:bytes=b"HTTP/1.1 200 OK\r\nContent-Length:0\r\n\r\n", dport:int=80)->List:
    src,dst=ctx["src"],ctx["dst"]; sport=random.randint(20000,65000)
    pk=tcp_3wh(src,dst,sport,dport); cli=pk[2][TCP].seq; srv=pk[2][TCP].ack
    a,cli,srv=tcp_send_cli(src,dst,sport,dport,cli,srv,req.encode()); pk+=a
    b,srv,cli=tcp_send_srv(dst,src,dport,sport,srv,cli,resp); pk+=b
    pk+=tcp_close(src,dst,sport,dport,cli,srv); return stamp(pk, time.time())

def flow_tls_clienthello(ctx:Dict[str,Any], sni:str)->List:
    src,dst=ctx["src"],ctx["dst"]; dport=443; sport=random.randint(20000,65000)
    pk=tcp_3wh(src,dst,sport,dport); cli=pk[2][TCP].seq; srv=pk[2][TCP].ack
    ch=build_clienthello_with_sni(sni)
    a,cli,srv=tcp_send_cli(src,dst,sport,dport,cli,srv,ch); pk+=a
    pk+=tcp_close(src,dst,sport,dport,cli,srv); return stamp(pk, time.time())

def flow_dns(ctx:Dict[str,Any], qname:str, qtype:str="A")->List:
    src,dst=ctx["src"],ctx["dst"]; sport=random.randint(20000,65000); qid=random.randint(1,65535)
    q=DNS(id=qid, rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    ans=DNSRR(rrname=qname, type=(1 if qtype=="A" else 16), rdata=("203.0.113.10" if qtype=="A" else "OK"))
    a=DNS(id=qid, qr=1, aa=1, qd=DNSQR(qname=qname, qtype=qtype), an=ans)
    p1=IP(src=src,dst=dst)/UDP(sport=sport,dport=53)/q
    p2=IP(src=dst,dst=src)/UDP(sport=53,dport=sport)/a
    return stamp([p1,p2], time.time(), 0.03)

def flow_syn_scan(ctx:Dict[str,Any], start:int=8000, cnt:int=20)->List:
    src,dst=ctx["src"],ctx["dst"]; sport=random.randint(1025,65535); seq=random.randint(1000,999999)
    pk=[IP(src=src,dst=dst)/TCP(sport=sport,dport=start+i,flags="S",seq=seq+i) for i in range(cnt)]
    return stamp(pk, time.time(), 0.004)

def easy_template(rule: Dict[str,str])->Tuple[str,Dict[str,Any]]:
    msg=(rule.get("msg") or "").lower(); proto=(rule.get("proto") or "").lower(); opts=(rule.get("full_options") or "").lower()
    if "dns" in proto or "dns.query" in opts: return "dns_basic", {"qname":"example.test","qtype":"A"}
    if "tls" in proto or "tls.sni" in opts:   return "tls_clienthello", {"sni":"example.test"}
    if "http" in proto or "http.host" in opts or "http.uri" in opts: return "http_get", {"req":"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}
    if "scan" in msg or "syn" in msg:         return "syn_scan", {"start":8000, "cnt":20}
    return "http_get", {"req":"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"}

def render_easy(ctx:Dict[str,Any], tmpl:str, params:Dict[str,Any])->List:
    if tmpl=="dns_basic": return flow_dns(ctx, params.get("qname","example.test"), params.get("qtype","A"))
    if tmpl=="tls_clienthello": return flow_tls_clienthello(ctx, params.get("sni","example.test"))
    if tmpl=="http_get": return flow_http(ctx, params.get("req","GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
    if tmpl=="syn_scan": return flow_syn_scan(ctx, params.get("start",8000), params.get("cnt",20))
    return flow_http(ctx, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")

# ======================= LLM + cache + logs ========================
OPENAI_API_KEY_SET = bool(os.getenv("OPENAI_API_KEY"))
OPENAI_IMPORT_OK = True
try:
    from openai import OpenAI
except Exception as e:
    OPENAI_IMPORT_OK = False
    logging.warning("openai SDK import 실패: %s. `pip install --upgrade openai` 필요.", e)
OPENAI_AVAILABLE = OPENAI_IMPORT_OK and OPENAI_API_KEY_SET
LOG.info("LLM flags: OPENAI_IMPORT_OK=%s, OPENAI_API_KEY_SET=%s", OPENAI_IMPORT_OK, OPENAI_API_KEY_SET)

PRIMARY_MODEL = os.getenv("OPENAI_MODEL_PRIMARY", "gpt-5-mini")
FALLBACK_MODEL = os.getenv("OPENAI_MODEL_FALLBACK", "gpt-5")

def ensure_dirs():
    Path("./log/llm").mkdir(parents=True, exist_ok=True)
    Path("./cache").mkdir(parents=True, exist_ok=True)

def _qna_path(sid: str, model: str) -> Path:
    return Path("./log/llm") / f"{sid}__by_{model}.qna"

def write_qna_log(
    sid: str,
    prompt: str,
    model: str,
    output_text: str,
    parsed: Dict[str,Any] | None = None,
    valid: bool | None = None,
    notes: str = "",
    llm_status: str = "",
    packet_count: int = 0,
    file_name: str = "",
    rule_rev: str = "",
    rule_gid: str = ""
):
    try:
        ensure_dirs()
        p = _qna_path(sid, model)
        with p.open("w", encoding="utf-8") as f:
            f.write(f"MODEL: {model}\n")
            f.write(f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"VALID: {valid}\n")
            f.write(f"LLM_STATUS: {llm_status}\n")
            f.write(f"NOTES: {notes}\n")
            if rule_rev: f.write(f"RULE_REV: {rule_rev}\n")
            if rule_gid: f.write(f"RULE_GID: {rule_gid}\n")
            if packet_count: f.write(f"PACKET_COUNT: {packet_count}\n")
            if file_name: f.write(f"FILE: {file_name}\n")
            f.write("=== PROMPT ===\n"); f.write(prompt or "")
            f.write("\n\n=== RAW OUTPUT ===\n"); f.write(output_text or "")
            if parsed:
                f.write("\n\n=== PARSED JSON ===\n"); f.write(json.dumps(parsed, ensure_ascii=False, indent=2))
                mult = parsed.get("multiplicity") or {}
                f.write("\n\n=== SUMMARY ===\n")
                f.write(f"attack_summary: {parsed.get('attack_summary','')}\n")
                f.write(f"packet_plan: {parsed.get('packet_plan','')}\n")
                f.write(f"multiplicity.src: {mult.get('src')}\n")
                f.write(f"multiplicity.dst: {mult.get('dst')}\n")
            f.write("\n")
    except Exception as e:
        LOG.warning("QnA log write failed for SID=%s: %s", sid, e)

def append_qna_meta(sid: str, model: str, packet_count: int, file_name: str, rule_rev: str, rule_gid: str):
    """생성 후 메타데이터(팩트)만 추가 기록"""
    try:
        p = _qna_path(sid, model)
        with p.open("a", encoding="utf-8") as f:
            if packet_count: f.write(f"\nPACKET_COUNT: {packet_count}\n")
            if file_name: f.write(f"FILE: {file_name}\n")
            if rule_rev: f.write(f"RULE_REV: {rule_rev}\n")
            if rule_gid: f.write(f"RULE_GID: {rule_gid}\n")
    except Exception as e:
        LOG.warning("QnA meta append failed for SID=%s: %s", sid, e)

class LLMCache:
    def __init__(self, db_path: Path = Path("./cache/llm_cache.db")):
        ensure_dirs()
        self.conn = sqlite3.connect(str(db_path), check_same_thread=False)
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS cache(
            key TEXT PRIMARY KEY, model TEXT, prompt TEXT, output TEXT, parsed TEXT, created REAL)""")
        self.conn.commit()

    def get(self, key: str) -> Optional[Dict[str,Any]]:
        r = self.conn.cursor().execute("SELECT model, prompt, output, parsed FROM cache WHERE key=?", (key,)).fetchone()
        if not r: return None
        model, prompt, output, parsed = r
        return {"model": model, "prompt": prompt, "output": output, "parsed": json.loads(parsed) if parsed else None}

    def put(self, key: str, model: str, prompt: str, output: str, parsed: Optional[Dict[str,Any]]):
        self.conn.cursor().execute("INSERT OR REPLACE INTO cache VALUES(?,?,?,?,?,?)",
                                   (key, model, prompt, output, json.dumps(parsed or {}), time.time()))
        self.conn.commit()

ALLOWED_TEMPLATES = {"http_request","dns_query","tls_clienthello","syn_scan"}

def compact_rule_for_llm(row: Dict[str,str]) -> str:
    """룰 전문 대신 핵심 요약(토큰 절감)."""
    msg=row.get("msg",""); proto=row.get("proto",""); ale=row.get("app-layer-event","")
    opts=row.get("full_options","")
    key_core, toks = extract_option_keys(opts)
    toks = toks[:5]
    return json.dumps({
        "msg": msg, "proto": proto, "app_layer_event": ale,
        "core_option_keys": key_core[:12], "option_tokens": toks
    }, ensure_ascii=False)

def validate_instr(obj: Dict[str,Any]) -> Tuple[bool, str]:
    for k in ("template_id","params","attack_summary","packet_plan"):
        if k not in obj: return False, f"missing:{k}"
    if obj["template_id"] not in ALLOWED_TEMPLATES: return False, f"bad_template:{obj['template_id']}"
    if len(str(obj["attack_summary"]))>160 and not ALLOW_LENIENT:
        return False, "attack_summary_too_long"
    if len(str(obj["packet_plan"]))>240 and not ALLOW_LENIENT:
        return False, "packet_plan_too_long"
    t=obj["template_id"]; p=obj.get("params") or {}
    if t=="http_request" and "method" not in p: return False, "http_missing_method"
    if t=="dns_query" and "qname" not in p: return False, "dns_missing_qname"
    if t=="tls_clienthello" and "sni" not in p: return False, "tls_missing_sni"
    if t=="syn_scan" and ("start" not in p or "cnt" not in p): return False, "scan_missing_params"
    mult=obj.get("multiplicity") or {}
    for side in ("src","dst"):
        s=mult.get(side) or {}; cnt=int(s.get("count",1))
        if cnt<1: return False, f"mult_{side}_count_lt1"
    return True, "ok"

def guess_template_hint(compact_json:str)->Optional[str]:
    try:
        j=json.loads(compact_json)
        proto=(j.get("proto","") or "").lower()
        toks=" ".join(j.get("option_tokens") or []).lower()
        msg=(j.get("msg","") or "").lower()
        if "dns" in proto or "dns.query" in toks: return "dns_query"
        if "tls" in proto or "tls.sni" in toks:   return "tls_clienthello"
        if "scan" in msg:                         return "syn_scan"
        if "http" in proto or "http." in toks:    return "http_request"
    except: pass
    return None

def build_prompt(compact_json:str, base_dst:str)->Tuple[str,str]:
    tmpl_hint = guess_template_hint(compact_json)
    hint = f"\n템플릿 힌트: template_id 후보는 '{tmpl_hint}'를 우선 고려." if tmpl_hint else ""
    system_msg = (
        "당신은 Suricata 룰 분석가이자 트래픽 생성 설계자입니다. "
        "출력은 반드시 JSON만 반환(설명 금지). 템플릿 후보는 {http_request,dns_query,tls_clienthello,syn_scan} 중 택1. "
        "스키마: {template_id:str, params:obj, multiplicity:{src:{strategy,count,spoof}, dst:{strategy,count}}, "
        "filename_hint?:str, attack_summary:str(<=120자), packet_plan:str(<=200자), rationale?:str}. "
        "실제 익스플로잇 금지. 리얼 플로우 전제."
    )
    user_msg = f"""
입력은 룰의 요약 JSON입니다. 해당 룰을 트리거하는 '정밀 패킷 생성 지시문(JSON)'만 출력하세요.
- attack_summary(공격/룰 해석 120자 이내), packet_plan(패킷 단계별 계획 200자 이내) 포함
- multiplicity:
  * SYN Flood/DDOS: src.strategy="random_public", count 32~256, spoof=true
  * Scan/Sweep: dst.strategy="c_class", count 16~64 (/24 기준 {base_dst})
  * 일반 단건: 모두 "single"
- 리얼 플로우 기본:
  * TCP: 3WH→클라이언트 요청→서버 200 응답→FIN/ACK
  * TLS: ClientHello(SNI)
  * DNS: Query/Response
[룰 요약]
{compact_json}
{hint}
JSON만 출력.
"""
    return system_msg, user_msg

def autofix_instr(obj: Dict[str, Any], compact_json: str) -> Tuple[Dict[str,Any], List[str]]:
    """누락 필드 자동 보정."""
    fixes=[]
    try:
        cj = json.loads(compact_json)
    except Exception:
        cj = {}
    t = obj.get("template_id","")
    p = obj.setdefault("params", {}) or {}
    if t == "dns_query":
        if not p.get("qname"):
            toks = " ".join(cj.get("option_tokens") or "")
            m = re.search(r'(?:=|:)([a-z0-9.-]+\.(?:com|net|org|io|xyz|top|biz|info|be|is))', toks, re.I)
            p["qname"] = (m.group(1) if m else "hard.example.test"); fixes.append("auto_fill:qname")
        if not p.get("qtype"): p["qtype"]="A"; fixes.append("auto_fill:qtype")
    elif t == "http_request":
        if not p.get("method"): p["method"]="GET"; fixes.append("auto_fill:http.method")
        hdr = p.setdefault("headers",{})
        if not hdr.get("Host"):
            toks = " ".join(cj.get("option_tokens") or "")
            m = re.search(r'http\.host=([a-z0-9.-]+\.[a-z]{2,})', toks, re.I)
            hdr["Host"] = (m.group(1) if m else "hard.example.test"); fixes.append("auto_fill:http.host")
        if not p.get("path"): p["path"]="/"; fixes.append("auto_fill:http.path")
        p.setdefault("body","")
    elif t == "tls_clienthello":
        if not p.get("sni"):
            toks = " ".join(cj.get("option_tokens") or "")
            m = re.search(r'tls\.sni=([a-z0-9.-]+\.[a-z]{2,})', toks, re.I)
            p["sni"] = (m.group(1) if m else "hard.example.test"); fixes.append("auto_fill:tls.sni")
    elif t == "syn_scan":
        if "start" not in p: p["start"]=8000; fixes.append("auto_fill:syn.start")
        if "cnt" not in p:   p["cnt"]=20;   fixes.append("auto_fill:syn.cnt")
    obj.setdefault("multiplicity", {"src":{"strategy":"single","count":1}, "dst":{"strategy":"single","count":1}})
    obj.setdefault("attack_summary","auto-filled summary")
    obj.setdefault("packet_plan","auto-filled plan")
    return obj, fixes

def ask_llm_with_models(compact_json: str, base_dst: str, sid: str, group_id: str, cache: 'LLMCache', use_llm: bool) -> Dict[str,Any]:
    """mini → (autofix 검증) → fixable 이슈면 mini 재시도 → 실패 시 fallback → 실패 시 휴리스틱"""
    if not use_llm or not OPENAI_AVAILABLE:
        if use_llm and not OPENAI_IMPORT_OK: LOG.warning("--use-llm 이지만 openai SDK 불가")
        elif use_llm and not OPENAI_API_KEY_SET: LOG.warning("--use-llm 이지만 OPENAI_API_KEY 미설정")
        obj = _fallback_instr_from_compact(compact_json)
        obj["_model_name"] = "heuristic"
        obj["_llm_status"] = "heuristic"
        return obj

    from openai import OpenAI
    client = OpenAI()
    cache_key = sha1s(f"{group_id}|{compact_json}")
    cached = cache.get(cache_key)
    if cached and cached.get("parsed"):
        LOG.info("LLM cache hit (group_id=%s)", group_id)
        # cache hit이어도 현재 SID로 로그를 남긴다
        try:
            model = cached.get("model") or "(cache)"
            prompt = cached.get("prompt")
            output = cached.get("output") or "[CACHED] raw output not stored"
            if not prompt:
                sys_msg, usr_msg = build_prompt(compact_json, base_dst)
                prompt = sys_msg + "\n\n" + usr_msg
            write_qna_log(
                sid, prompt, model, output,
                parsed=cached["parsed"], valid=True, notes="cache_hit", llm_status="cache_hit"
            )
        except Exception as e:
            LOG.warning("cache-hit 로그 기록 실패(SID=%s): %s", sid, e)
        obj = dict(cached["parsed"])
        obj["_model_name"] = cached.get("model") or "cache"
        obj["_llm_status"] = "cache_hit"
        return obj

    def call_model(model_name: str, force_template: Optional[str]=None):
        system_msg, user_msg = build_prompt(compact_json, base_dst)
        if force_template:
            user_msg += f"\n\n제약: template_id는 반드시 '{force_template}' 로 고정. 해당 템플릿에 필요한 params를 모두 채워라."
        resp = client.chat.completions.create(
            model=model_name,
            messages=[{"role":"system","content":system_msg},{"role":"user","content":user_msg}]
        )
        txt = resp.choices[0].message.content or ""
        m = re.search(r"\{.*\}", txt, re.S)
        obj = json.loads(m.group(0)) if m else json.loads(txt)
        # 자동 보정 → 검증
        obj, fixes = autofix_instr(obj, compact_json)
        ok, reason = validate_instr(obj)
        status = "fresh_primary_retry" if force_template else "fresh_primary"
        write_qna_log(
            sid, system_msg+"\n\n"+user_msg, model_name, txt,
            parsed=obj, valid=ok, notes=(reason + ((" | "+",".join(fixes)) if fixes else "")),
            llm_status=status
        )
        return obj, ok, reason, system_msg+"\n\n"+user_msg, txt, status

    # 1차: primary
    try:
        obj, ok, reason, prmpt, raw, status = call_model(PRIMARY_MODEL)
        if ok:
            obj["_model_name"] = PRIMARY_MODEL; obj["_llm_status"] = status
            cache.put(sha1s(f"{group_id}|{compact_json}"), PRIMARY_MODEL, prmpt, raw, obj)
            return obj
        # fixable이면 mini로 재시도 (템플릿 고정)
        if reason in RETRY_FIXABLE:
            force = {
                "dns_missing_qname": "dns_query",
                "http_missing_method": "http_request",
                "tls_missing_sni": "tls_clienthello",
                "scan_missing_params": "syn_scan",
            }[reason]
            obj, ok, reason, prmpt, raw, status = call_model(PRIMARY_MODEL, force_template=force)
            if ok:
                obj["_model_name"] = PRIMARY_MODEL; obj["_llm_status"] = status
                cache.put(sha1s(f"{group_id}|{compact_json}"), PRIMARY_MODEL, prmpt, raw, obj)
                return obj
            LOG.warning("LLM(primary 재시도) 실패: %s → fallback", reason)
        else:
            LOG.warning("LLM(primary) 검증실패: %s → fallback", reason)
    except Exception as e:
        LOG.warning("LLM(primary=%s) 호출/파싱 예외: %s → fallback", PRIMARY_MODEL, e)

    # 2차: fallback
    try:
        system_msg, user_msg = build_prompt(compact_json, base_dst)
        resp = client.chat.completions.create(
            model=FALLBACK_MODEL,
            messages=[{"role":"system","content":system_msg},{"role":"user","content":user_msg}]
        )
        txt = resp.choices[0].message.content or ""
        m = re.search(r"\{.*\}", txt, re.S)
        obj = json.loads(m.group(0)) if m else json.loads(txt)
        obj, fixes = autofix_instr(obj, compact_json)
        ok, reason = validate_instr(obj)
        write_qna_log(sid, system_msg+"\n\n"+user_msg, FALLBACK_MODEL, txt,
                      parsed=obj, valid=ok, notes=(reason + ((" | "+",".join(fixes)) if fixes else "")),
                      llm_status="fresh_fallback")
        if ok:
            obj["_model_name"] = FALLBACK_MODEL; obj["_llm_status"]="fresh_fallback"
            cache.put(sha1s(f"{group_id}|{compact_json}"), FALLBACK_MODEL, system_msg+"\n\n"+user_msg, txt, obj)
            return obj
        LOG.warning("LLM(fallback=%s) 검증실패: %s → 휴리스틱", FALLBACK_MODEL, reason)
    except Exception as e:
        LOG.warning("LLM(fallback=%s) 호출/파싱 예외: %s → 휴리스틱", FALLBACK_MODEL, e)

    obj = _fallback_instr_from_compact(compact_json)
    obj["_model_name"] = "heuristic"; obj["_llm_status"] = "heuristic"
    return obj

def _fallback_instr_from_compact(compact_json: str)->Dict[str,Any]:
    try:
        j = json.loads(compact_json)
    except Exception:
        return {"template_id":"http_request","params":{"method":"GET","path":"/","headers":{"Host":"hard.example.test"},"body":""},
                "multiplicity":{"src":{"strategy":"single","count":1},"dst":{"strategy":"single","count":1}},
                "filename_hint":"generic_http","attack_summary":"HTTP 기반 탐지 가정","packet_plan":"3WH→HTTP 요청→200 응답→FIN/ACK"}
    msg = (j.get("msg") or "").lower()
    proto = (j.get("proto") or "").lower()
    toks = " ".join(j.get("option_tokens") or [])
    if re.search(r'\b(ddos|syn[\s_-]*flood|flood)\b', msg+toks):
        return {"template_id":"syn_scan","params":{"start":80,"cnt":64},
                "multiplicity":{"src":{"strategy":"random_public","count":128,"spoof":True},"dst":{"strategy":"single","count":1}},
                "filename_hint":"ddos_syn_like","attack_summary":"SYN Flood/DDOS 추정","packet_plan":"짧은 간격의 TCP SYN 다량 송신"}
    if re.search(r'\b(scan|portscan|masscan|nmap|sweep)\b', msg+toks):
        return {"template_id":"syn_scan","params":{"start":8000,"cnt":20},
                "multiplicity":{"src":{"strategy":"single","count":1},"dst":{"strategy":"c_class","count":32}},
                "filename_hint":"scan_like","attack_summary":"스캔 패턴 추정","packet_plan":"다수 포트/호스트에 SYN 송신"}
    if "dns" in proto or "dns.query" in toks:
        return {"template_id":"dns_query","params":{"qname":"hard.example.test","qtype":"A"},
                "multiplicity":{"src":{"strategy":"single","count":1},"dst":{"strategy":"single","count":1}},
                "filename_hint":"dns_like","attack_summary":"DNS 매칭","packet_plan":"DNS Query/Response 페어"}
    if "tls" in proto or "tls.sni" in toks:
        return {"template_id":"tls_clienthello","params":{"sni":"hard.example.test"},
                "multiplicity":{"src":{"strategy":"single","count":1},"dst":{"strategy":"single","count":1}},
                "filename_hint":"tls_sni","attack_summary":"TLS SNI 기반","packet_plan":"ClientHello(SNI)"}
    return {"template_id":"http_request","params":{"method":"GET","path":"/abc","headers":{"Host":"hard.example.test"},"body":""},
            "multiplicity":{"src":{"strategy":"single","count":1},"dst":{"strategy":"single","count":1}},
            "filename_hint":"http_get","attack_summary":"HTTP Host/URI/Content 매칭 가정","packet_plan":"3WH→HTTP 요청→200 응답→FIN/ACK"}

def render_from_instruction(ctx:Dict[str,Any], instr:Dict[str,Any])->List:
    tid = instr.get("template_id","http_request"); p = instr.get("params",{}) or {}
    if tid in ("http_request","http"):
        method=p.get("method","GET"); path=p.get("path","/"); headers=p.get("headers",{}) or {}; body=p.get("body","")
        if "Host" not in headers: headers["Host"]="example.test"
        lines=[f"{method} {path} HTTP/1.1"] + [f"{k}: {v}" for k,v in headers.items()]
        req="\r\n".join(lines)+("\r\n\r\n"+body if body else "\r\n\r\n")
        return flow_http(ctx, req)
    if tid in ("dns_query","dns"): return flow_dns(ctx, p.get("qname","hard.example.test"), p.get("qtype","A"))
    if tid in ("tls_clienthello","tls"): return flow_tls_clienthello(ctx, p.get("sni","hard.example.test"))
    if tid in ("syn_scan","scan"): return flow_syn_scan(ctx, int(p.get("start",8000)), int(p.get("cnt",20)))
    return flow_http(ctx, "GET / HTTP/1.1\r\nHost: hard.example.test\r\n\r\n")

# ======================= multiplicity helpers ======================
PRIVATE_NETS = [ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
                ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
                ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("224.0.0.0/4"),
                ipaddress.ip_network("240.0.0.0/4")]
def is_public_ipv4(ip: str) -> bool:
    try:
        ip4 = ipaddress.ip_address(ip)
        if ip4.version != 4: return False
        for n in PRIVATE_NETS:
            if ip4 in n: return False
        return True
    except Exception:
        return False
def random_public_ipv4() -> str:
    while True:
        ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
        if is_public_ipv4(ip): return ip
def expand_c_class(dst: str, count: int) -> List[str]:
    try:
        a,b,c,_ = [int(x) for x in dst.split(".")]
    except Exception:
        return [dst]
    pool=list(range(1,255)); random.shuffle(pool)
    out=[dst]
    for i in pool:
        if len(out)>=count: break
        cand=f"{a}.{b}.{c}.{i}"
        if cand!=dst: out.append(cand)
    return out[:count]
def multiplicity_from_instruction(instr: Dict[str,Any], base_src: str, base_dst: str, cap_src:int, cap_dst:int) -> Tuple[List[str], List[str]]:
    mult = instr.get("multiplicity") or {}
    s = (mult.get("src") or {}); d = (mult.get("dst") or {})
    s_strategy=(s.get("strategy") or "single").lower(); s_count=max(1, min(int(s.get("count",1)), cap_src))
    d_strategy=(d.get("strategy") or "single").lower(); d_count=max(1, min(int(d.get("count",1)), cap_dst))
    srcs=[random_public_ipv4() for _ in range(s_count)] if s_strategy=="random_public" else [base_src]
    dsts=expand_c_class(base_dst, d_count) if d_strategy=="c_class" else [base_dst]
    return srcs, dsts
def multiplicity_from_heuristic(msg_proto_opts:str, base_src:str, base_dst:str, cap_src:int, cap_dst:int)->Tuple[List[str], List[str]]:
    rt=msg_proto_opts.lower()
    if re.search(r'\b(ddos|syn[\s_-]*flood|flood)\b', rt): return [random_public_ipv4() for _ in range(min(128, cap_src))], [base_dst]
    if re.search(r'\b(scan|portscan|masscan|nmap|sweep)\b', rt): return [base_src], expand_c_class(base_dst, min(32, cap_dst))
    return [base_src], [base_dst]

# ====================== selection & naming =========================
def pcap_name(sid:str, msg:str, src:str, dst:str, group_id:str,
              model_name:str="unknown", rev:str="", pkt_len:int=0)->str:
    parts = [
        sid or "NA",
        slug(msg, 30),
        f"SRC_{src.replace('.','-')}",
        f"DST_{dst.replace('.','-')}",
        group_id,
        f"by_{model_name}",
    ]
    if rev:
        parts.append(f"v{rev}")
    if pkt_len:
        parts.append(f"L{pkt_len}")
    return "__".join(parts) + ".pcap"

def select_mix(easy_df: pd.DataFrame, hard_df: pd.DataFrame, total:int=50, easy_n:int=30)->pd.DataFrame:
    easy_n=min(easy_n,total); hard_n=total-easy_n
    easy_pick = easy_df.sample(n=min(easy_n, len(easy_df)), random_state=42) if len(easy_df)>0 else easy_df.head(0)
    hard_pick = hard_df.sample(n=min(hard_n, len(hard_df)), random_state=1337) if len(hard_df)>0 else hard_df.head(0)
    return pd.concat([easy_pick, hard_pick], ignore_index=True)

# ============================== Runner =============================
@dataclass
class RunConfig:
    rules_path: Optional[Path]; parsed_csv: Optional[Path]
    dst: str; src: str
    out_dir: Path; single_pcap: Optional[Path]
    count: int; easy_count: int; use_llm: bool
    cap_src: int; cap_dst: int
    max_pkts: int

def load_rules(cfg: RunConfig) -> pd.DataFrame:
    if cfg.parsed_csv:
        LOG.info("Loading parsed CSV: %s", cfg.parsed_csv)
        df = pd.read_csv(cfg.parsed_csv, dtype=str).fillna("")
        required = {"sid","proto","msg","full_options","full_rule","app-layer-event"}
        missing = [c for c in required if c not in df.columns]
        if missing: raise ValueError(f"Parsed CSV missing columns: {missing}")
        return df
    elif cfg.rules_path:
        LOG.info("Parsing rules file: %s", cfg.rules_path)
        return parse_rules_file(cfg.rules_path)
    else:
        raise ValueError("Either --rules or --parsed must be provided.")

def run(cfg: RunConfig):
    df = load_rules(cfg)
    if df.empty: LOG.error("No rules available."); return
    df = group_rules(df)
    easy_df, hard_df = split_difficulty(df)
    LOG.info("Total=%d, Easy=%d, Hard=%d", len(df), len(easy_df), len(hard_df))
    target = select_mix(easy_df, hard_df, total=cfg.count, easy_n=cfg.easy_count)
    LOG.info("Selected %d rules (easy=%d, hard=%d)", len(target),
             sum(target.index.isin(easy_df.index)), sum(target.index.isin(hard_df.index)))

    all_pkts=[]; cache = LLMCache()
    if not cfg.single_pcap: cfg.out_dir.mkdir(parents=True, exist_ok=True)

    for _, r in target.iterrows():
        sid=str(r.get("sid") or ""); msg=r.get("msg",""); gid=r.get("group_id","nogroup")
        rule_text=r.get("full_rule",""); is_easy = r.name in easy_df.index
        rev=str(r.get("rev") or ""); gid_str=str(r.get("gid") or "")

        if is_easy:
            instr={"multiplicity": None, "_model_name":"easy", "_llm_status":"easy"}
        else:
            compact = compact_rule_for_llm(r.to_dict())
            instr = ask_llm_with_models(compact, cfg.dst, sid, gid, cache, cfg.use_llm)

        # multiplicity
        if instr and instr.get("multiplicity"):
            src_candidates, dst_candidates = multiplicity_from_instruction(instr, cfg.src, cfg.dst, cfg.cap_src, cfg.cap_dst)
        else:
            src_candidates, dst_candidates = multiplicity_from_heuristic(rule_text, cfg.src, cfg.dst, cfg.cap_src, cfg.cap_dst)

        model_name = instr.get("_model_name","unknown")
        llm_status = instr.get("_llm_status","")

        for s in src_candidates:
            for d in dst_candidates:
                ctx={"src":s,"dst":d}
                # 생성
                try:
                    if is_easy:
                        tmpl, params = easy_template(r.to_dict())
                        pkts = render_easy(ctx, tmpl, params)
                    else:
                        pkts = render_from_instruction(ctx, instr)
                    # max_pkts 상한 적용
                    if cfg.max_pkts and len(pkts) > cfg.max_pkts:
                        LOG.warning("Truncated SID=%s to %d packets (was %d)", sid, cfg.max_pkts, len(pkts))
                        pkts = pkts[:cfg.max_pkts]
                    pkt_len = len(pkts)

                    # 파일명 생성 (by_model, vrev, Llen 포함)
                    name = pcap_name(sid, msg, s, d, gid, model_name, rev, pkt_len)

                    if cfg.single_pcap:
                        all_pkts.extend(pkts)
                    else:
                        out = cfg.out_dir / name
                        wrpcap(str(out), pkts)
                        LOG.info("Wrote %s (packets=%d)", out, pkt_len)

                    # LLM 로그가 있는 경우 메타데이터 append
                    if model_name not in ("easy",):
                        # 파일 경로 (single_pcap일 때는 실제 파일명 모를 수 있으니 생략 가능)
                        file_path_str = str(cfg.single_pcap if cfg.single_pcap else (cfg.out_dir / name))
                        append_qna_meta(sid, model_name, pkt_len, file_path_str, rev, gid_str)

                except Exception as e:
                    LOG.exception("Failed SID=%s (%s->%s): %s", sid, s, d, e)

    if cfg.single_pcap and all_pkts:
        outp = cfg.single_pcap if str(cfg.single_pcap).endswith(".pcap") else cfg.single_pcap.with_suffix(".pcap")
        wrpcap(str(outp), all_pkts); LOG.info("Wrote combined PCAP: %s (packets=%d)", outp, len(all_pkts))

def main():
    ap = argparse.ArgumentParser(description="Suricata rules pilot PCAP generator (mini→autofix→retry→fallback + 캐시 + 축약입력)")
    src_rules = ap.add_mutually_exclusive_group(required=True)
    src_rules.add_argument("--rules", help="Path to suricata.rules (raw). If provided, program will parse it.")
    src_rules.add_argument("--parsed", help="Path to parsed Suricata CSV (suricata_rules_parsed.csv). If provided, parsing is skipped.")
    ap.add_argument("--dst", required=True, help="Destination/server IP (sensor)")
    ap.add_argument("--src", default="192.168.56.10", help="Source/client base IP [default: 192.168.56.10]")
    ap.add_argument("--out", default="outputs/pcaps", help="Per-rule PCAP directory (disabled if --single-pcap)")
    ap.add_argument("--single-pcap", default=None, help="Write all flows into one PCAP (e.g., outputs/all_50.pcap)")
    ap.add_argument("--count", type=int, default=50, help="How many rules to test [default: 50]")
    ap.add_argument("--easy-count", type=int, default=30, help="How many from easy set [default: 30]")
    ap.add_argument("--use-llm", action="store_true", help="If set, ask LLM for hard rules (needs OPENAI_API_KEY)")
    ap.add_argument("--cap-src", type=int, default=256, help="Upper cap for source multiplicity [default: 256]")
    ap.add_argument("--cap-dst", type=int, default=64, help="Upper cap for destination multiplicity [default: 64]")
    ap.add_argument("--max-pkts", type=int, default=0, help="Max packets per flow/file (0 = unlimited)")
    args = ap.parse_args()

    run(RunConfig(
        rules_path=Path(args.rules) if args.rules else None,
        parsed_csv=Path(args.parsed) if args.parsed else None,
        dst=args.dst, src=args.src,
        out_dir=Path(args.out),
        single_pcap=Path(args.single_pcap) if args.single_pcap else None,
        count=args.count, easy_count=args.easy_count,
        use_llm=bool(args.use_llm), cap_src=int(args.cap_src), cap_dst=int(args.cap_dst),
        max_pkts=int(args.max_pkts),
    ))

if __name__ == "__main__":
    main()
