#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pkgen_by_suricata_rules_pilot.py

- (--parsed CSV) 주면 파싱 생략, 아니면 (--rules)에서 Suricata 룰 파싱
- 룰을 그룹핑(group_id)하고 쉬움/어려움 분리 → 약 50개 샘플 생성(튜닝 가능)
- 쉬운 룰: 내장 리얼 플로우(3-way, 서버 응답, 정상 종료 / DNS Q/R / TLS ClientHello / SYN scan)
- 어려운 룰: --use-llm 시 GPT에 질의하여 '지시문 JSON' 수신 → 엔진 렌더
  * 질의/응답은 ./log/llm/<sid>.qna 로 기록
  * SDK/키/네트워크 이슈 시 휴리스틱으로 대체
- 공격 성격별 multiplicity(소스/목적지 다중화)를 LLM 또는 휴리스틱으로 결정
  * SYN Flood/DDOS → random public src 다수(스푸핑 가정)
  * Scan/Sweep → 대상 /24 대역 fan-out
- 안전상한: --cap-src(기본 256), --cap-dst(기본 64)
- PCAP 파일명: "<sid>__<msg_slug>__SRC_<src>__DST_<dst>__<group_id>.pcap"

예시
  python pkgen_by_suricata_rules_pilot.py --parsed suricata_rules_parsed.csv --dst 192.0.2.10 --src 192.168.56.10 --out outputs/pcaps
  python pkgen_by_suricata_rules_pilot.py --rules suricata.rules --dst 192.0.2.10 --use-llm --single-pcap outputs/all_50.pcap
"""

import argparse, os, re, json, random, time, hashlib, logging, ipaddress
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, List, Tuple, Optional

import pandas as pd
from scapy.all import IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR, wrpcap

LOG = logging.getLogger("pkgen")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# -------------------- utils --------------------
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

# -------------------- parse rules --------------------
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
        v = opts.get(k)
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

# -------------------- grouping --------------------
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

# -------------------- difficulty split --------------------
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

# -------------------- flow builders --------------------
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

# -------------------- LLM (chat.completions) --------------------
OPENAI_API_KEY_SET = bool(os.getenv("OPENAI_API_KEY"))
OPENAI_IMPORT_OK = True
try:
    from openai import OpenAI
except Exception as e:
    OPENAI_IMPORT_OK = False
    logging.warning("openai SDK import 실패: %s. `pip install --upgrade openai` 필요.", e)

OPENAI_AVAILABLE = OPENAI_IMPORT_OK and OPENAI_API_KEY_SET
LOG.info("LLM flags: OPENAI_IMPORT_OK=%s, OPENAI_API_KEY_SET=%s", OPENAI_IMPORT_OK, OPENAI_API_KEY_SET)

def write_qna_log(sid: str, prompt: str, model: str, output_text: str):
    try:
        outdir = Path("./log/llm")
        outdir.mkdir(parents=True, exist_ok=True)
        p = outdir / f"{sid}.qna"
        with p.open("w", encoding="utf-8") as f:
            f.write(f"MODEL: {model}\n")
            f.write(f"TIME: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=== PROMPT ===\n")
            f.write(prompt)
            f.write("\n\n=== OUTPUT ===\n")
            f.write(output_text)
            f.write("\n")
    except Exception as e:
        LOG.warning("QnA log write failed for SID=%s: %s", sid, e)

def _fallback_instr(rule_text: str) -> Dict[str,Any]:
    rt = (rule_text or "").lower()
    if re.search(r'\b(ddos|syn[\s_-]*flood|flood)\b', rt):
        mult = {"src":{"strategy":"random_public","count":128,"spoof":True}, "dst":{"strategy":"single","count":1}}
    elif re.search(r'\b(scan|portscan|masscan|nmap|sweep)\b', rt):
        mult = {"src":{"strategy":"single","count":1}, "dst":{"strategy":"c_class","count":32}}
    else:
        mult = {"src":{"strategy":"single","count":1}, "dst":{"strategy":"single","count":1}}
    if "dns" in rt or "dns.query" in rt:
        return {"template_id":"dns_query","params":{"qname":"hard.example.test","qtype":"A"},"multiplicity":mult,"filename_hint":"dns_like"}
    if "tls" in rt or "tls.sni" in rt:
        return {"template_id":"tls_clienthello","params":{"sni":"hard.example.test"},"multiplicity":mult,"filename_hint":"tls_sni"}
    if "http" in rt or "host" in rt or "uri" in rt:
        return {"template_id":"http_request","params":{"method":"GET","path":"/abc","headers":{"Host":"hard.example.test"},"body":""},"multiplicity":mult,"filename_hint":"http_get"}
    return {"template_id":"http_request","params":{"method":"GET","path":"/","headers":{"Host":"hard.example.test"},"body":""},"multiplicity":mult,"filename_hint":"generic_http"}

def ask_llm_for_instruction(rule_text:str, group_sig:str, base_dst:str, sid:str, use_llm:bool)->Dict[str,Any]:
    if not use_llm or not OPENAI_AVAILABLE:
        if use_llm and not OPENAI_IMPORT_OK:
            LOG.warning("--use-llm 지정됨, 그러나 openai SDK 미설치/불러오기 실패.")
        elif use_llm and not OPENAI_API_KEY_SET:
            LOG.warning("--use-llm 지정됨, 그러나 OPENAI_API_KEY 환경변수 미설정.")
        return _fallback_instr(rule_text)

    client = OpenAI()
    model_name = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    system_msg = (
        "당신은 Suricata 룰 분석가입니다. 출력은 반드시 JSON만 반환하세요. "
        "스키마: {template_id:str, params:obj, multiplicity:{src:{strategy,count,spoof}, dst:{strategy,count}}, "
        "filename_hint?:str, rationale?:str}. 실제 익스플로잇 금지. 리얼 플로우 전제."
    )
    user_msg = f"""
목표: 룰을 트리거하는 '정밀 패킷 생성 지시문(JSON)'만 출력.
- multiplicity 결정:
  - SYN Flood/DDOS: src.strategy="random_public", count 32~256, spoof=true
  - Port scan/sweep: dst.strategy="c_class", count 16~64 (/24 기준은 {base_dst})
  - 일반 단건: 모두 "single"
[입력 룰]
{rule_text}

[그룹 시그니처]
{group_sig}
JSON만 출력하세요.
"""
    try:
        resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role":"system","content":system_msg},
                {"role":"user","content":user_msg},
            ]            
        )
        txt = resp.choices[0].message.content or ""
        write_qna_log(sid, system_msg + "\n\n" + user_msg, model_name, txt)

        # JSON만 추출 (```json ... ``` 감싸온 경우 포함)
        m = re.search(r"\{.*\}", txt, re.S)
        if m:
            return json.loads(m.group(0))
        return json.loads(txt)
    except Exception as e:
        LOG.warning("LLM 호출/파싱 실패(SID=%s): %s → 휴리스틱 사용", sid, e)
        try:
            write_qna_log(sid, system_msg + "\n\n" + user_msg, model_name, f"[EXCEPTION] {e}")
        except Exception:
            pass
        return _fallback_instr(rule_text)

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

# -------------------- multiplicity helpers --------------------
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
    try:
        a,b,c,_ = [int(x) for x in dst.split(".")]
    except Exception:
        return [dst]
    pool = [i for i in range(1,255)]
    random.shuffle(pool)
    out = [dst]
    for i in pool:
        if len(out) >= count: break
        cand = f"{a}.{b}.{c}.{i}"
        if cand != dst:
            out.append(cand)
    return out[:count]

def multiplicity_from_instruction(instr: Dict[str,Any], base_src: str, base_dst: str, cap_src:int, cap_dst:int) -> Tuple[List[str], List[str]]:
    srcs = [base_src]; dsts=[base_dst]
    mult = instr.get("multiplicity") or {}
    s = mult.get("src") or {}
    d = mult.get("dst") or {}

    s_strategy = (s.get("strategy") or "single").lower()
    s_count = max(1, min(int(s.get("count", 1)), cap_src))
    if s_strategy == "random_public":
        srcs = [random_public_ipv4() for _ in range(s_count)]
    else:
        srcs = [base_src]

    d_strategy = (d.get("strategy") or "single").lower()
    d_count = max(1, min(int(d.get("count", 1)), cap_dst))
    if d_strategy == "c_class":
        dsts = expand_c_class(base_dst, d_count)
    else:
        dsts = [base_dst]

    return srcs, dsts

def multiplicity_from_heuristic(rule_text:str, base_src:str, base_dst:str, cap_src:int, cap_dst:int)->Tuple[List[str], List[str]]:
    rt = (rule_text or "").lower()
    if re.search(r'\b(ddos|syn[\s_-]*flood|flood)\b', rt):
        return [random_public_ipv4() for _ in range(min(128, cap_src))], [base_dst]
    if re.search(r'\b(scan|portscan|masscan|nmap|sweep)\b', rt):
        return [base_src], expand_c_class(base_dst, min(32, cap_dst))
    return [base_src], [base_dst]

# -------------------- selection & naming --------------------
def select_mix(easy_df: pd.DataFrame, hard_df: pd.DataFrame, total:int=50, easy_n:int=30)->pd.DataFrame:
    easy_n = min(easy_n, total)
    hard_n = total - easy_n
    easy_pick = easy_df.sample(n=min(easy_n, len(easy_df)), random_state=42) if len(easy_df)>0 else easy_df.head(0)
    hard_pick = hard_df.sample(n=min(hard_n, len(hard_df)), random_state=1337) if len(hard_df)>0 else hard_df.head(0)
    return pd.concat([easy_pick, hard_pick], ignore_index=True)

def pcap_name(sid:str, msg:str, src:str, dst:str, group_id:str)->str:
    return f"{sid or 'NA'}__{slug(msg, 30)}__SRC_{src.replace('.','-')}__DST_{dst.replace('.','-')}__{group_id}.pcap"

# -------------------- Runner --------------------
@dataclass
class RunConfig:
    rules_path: Optional[Path]
    parsed_csv: Optional[Path]
    dst: str
    src: str
    out_dir: Path
    single_pcap: Optional[Path]
    count: int
    easy_count: int
    use_llm: bool
    cap_src: int
    cap_dst: int

def load_rules(cfg: RunConfig) -> pd.DataFrame:
    if cfg.parsed_csv:
        LOG.info("Loading parsed CSV: %s", cfg.parsed_csv)
        df = pd.read_csv(cfg.parsed_csv, dtype=str).fillna("")
        required = {"sid","proto","msg","full_options","full_rule"}
        missing = [c for c in required if c not in df.columns]
        if missing:
            raise ValueError(f"Parsed CSV missing columns: {missing}")
        return df
    elif cfg.rules_path:
        LOG.info("Parsing rules file: %s", cfg.rules_path)
        return parse_rules_file(cfg.rules_path)
    else:
        raise ValueError("Either --rules or --parsed must be provided.")

def run(cfg: RunConfig):
    df = load_rules(cfg)
    if df.empty:
        LOG.error("No rules available.")
        return
    df = group_rules(df)

    easy_df, hard_df = split_difficulty(df)
    LOG.info("Total=%d, Easy=%d, Hard=%d", len(df), len(easy_df), len(hard_df))
    target = select_mix(easy_df, hard_df, total=cfg.count, easy_n=cfg.easy_count)
    LOG.info("Selected %d rules (easy=%d, hard=%d)", len(target),
             sum(target.index.isin(easy_df.index)), sum(target.index.isin(hard_df.index)))

    all_pkts=[]
    if not cfg.single_pcap:
        cfg.out_dir.mkdir(parents=True, exist_ok=True)

    for _, r in target.iterrows():
        sid = str(r.get("sid") or "")
        msg = r.get("msg","")
        gid = r.get("group_id","nogroup")
        rule_text = r.get("full_rule","")
        is_easy = r.name in easy_df.index

        # instruction (hard rules → LLM/heuristic). easy도 multiplicity는 휴리스틱 사용
        if is_easy:
            instr = {"multiplicity": None}
        else:
            instr = ask_llm_for_instruction(rule_text, r.get("group_signature",""), cfg.dst, sid, cfg.use_llm)

        # multiplicity 결정
        if instr and instr.get("multiplicity"):
            src_candidates, dst_candidates = multiplicity_from_instruction(instr, cfg.src, cfg.dst, cfg.cap_src, cfg.cap_dst)
        else:
            src_candidates, dst_candidates = multiplicity_from_heuristic(rule_text, cfg.src, cfg.dst, cfg.cap_src, cfg.cap_dst)

        for s in src_candidates:
            for d in dst_candidates:
                ctx = {"src": s, "dst": d}
                name = pcap_name(sid, msg, s, d, gid)
                try:
                    if is_easy:
                        tmpl, params = easy_template(r.to_dict())
                        pkts = render_easy(ctx, tmpl, params)
                    else:
                        pkts = render_from_instruction(ctx, instr)
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
    ap = argparse.ArgumentParser(description="Suricata rules pilot PCAP generator (with per-rule multiplicity & LLM QnA logs)")
    src_rules = ap.add_mutually_exclusive_group(required=True)
    src_rules.add_argument("--rules", help="Path to suricata.rules (raw). If provided, program will parse it.")
    src_rules.add_argument("--parsed", help="Path to parsed Suricata CSV (suricata_rules_parsed.csv). If provided, parsing is skipped.")
    ap.add_argument("--dst", required=True, help="Destination/server IP (sensor) e.g., 192.0.2.10")
    ap.add_argument("--src", default="192.168.56.10", help="Source/client base IP [default: 192.168.56.10]")
    ap.add_argument("--out", default="outputs/pcaps", help="Per-rule PCAP directory (disabled if --single-pcap)")
    ap.add_argument("--single-pcap", default=None, help="Write all flows into one PCAP (e.g., outputs/all_50.pcap)")
    ap.add_argument("--count", type=int, default=50, help="How many rules to test [default: 50]")
    ap.add_argument("--easy-count", type=int, default=30, help="How many from easy set [default: 30]")
    ap.add_argument("--use-llm", action="store_true", help="If set, try GPT for hard rules (needs OPENAI_API_KEY)")
    ap.add_argument("--cap-src", type=int, default=256, help="Upper cap for source multiplicity [default: 256]")
    ap.add_argument("--cap-dst", type=int, default=64, help="Upper cap for destination multiplicity [default: 64]")
    args = ap.parse_args()

    run(RunConfig(
        rules_path=Path(args.rules) if args.rules else None,
        parsed_csv=Path(args.parsed) if args.parsed else None,
        dst=args.dst,
        src=args.src,
        out_dir=Path(args.out),
        single_pcap=Path(args.single_pcap) if args.single_pcap else None,
        count=args.count,
        easy_count=args.easy_count,
        use_llm=bool(args.use_llm),
        cap_src=int(args.cap_src),
        cap_dst=int(args.cap_dst),
    ))

if __name__ == "__main__":
    main()
