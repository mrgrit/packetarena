#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Suricata/Snort rules -> CSV parser

- 단일/표준 형태의 룰을 안정적으로 파싱
- 따옴표 안의 세미콜론을 보존하며 옵션 분해
- 헤더(action, proto, src, src_port, direction, dst, dst_port) 및 주요 옵션 필드 추출
- 원문 옵션/룰 전체 문자열 보존

Usage:
  python parse_suricata_rules.py --in suricata.rules --out suricata_rules_parsed.csv
  python parse_suricata_rules.py --in suricata.rules --out out.csv --include-disabled
"""

import argparse
import csv
import re
from pathlib import Path

RULE_RE = re.compile(
    r'^\s*(alert|drop|reject|pass|log)\s+[^\n]*?\([^\)]*\)\s*;?\s*$',
    re.IGNORECASE | re.MULTILINE,
)

# 따옴표 안의 ; 는 분할하지 않음
SPLIT_OPTS_RE = re.compile(r';\s*(?=(?:[^"]*"[^"]*")*[^"]*$)')

def join_continuations(text: str) -> str:
    """
    역슬래시(\\)로 줄바꿈한 룰을 한 줄로 합쳐준다.
    (suricata.rules가 대개 한 줄 룰이지만 대비용)
    """
    lines = text.splitlines()
    buf, curr = [], []
    for ln in lines:
        if ln.rstrip().endswith("\\"):
            curr.append(ln.rstrip()[:-1] + " ")
        else:
            curr.append(ln)
            buf.append("".join(curr))
            curr = []
    if curr:
        buf.append("".join(curr))
    return "\n".join(buf)

def parse_options_block(options_block: str):
    """
    옵션 블록을 dict(key->list[str])로 변환
    """
    opts_map = {}
    if not options_block:
        return opts_map
    parts = [p.strip() for p in SPLIT_OPTS_RE.split(options_block) if p.strip()]
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            k = k.strip()
            v = v.strip()
            if len(v) >= 2 and v[0] == '"' and v[-1] == '"':
                v = v[1:-1]
            opts_map.setdefault(k, []).append(v)
        else:
            k = p.strip()
            opts_map.setdefault(k, []).append("")
    return opts_map

def first(opts_map, key):
    vals = opts_map.get(key)
    return (vals[0].strip() if vals else "")

def parse_rule_line(rule: str):
    """
    룰 문자열 -> (헤더 필드 + 주요 옵션 필드) dict
    """
    # 헤더/옵션 분리
    if "(" not in rule or ")" not in rule:
        return None
    header, rest = rule.split("(", 1)
    options_block = rest.rsplit(")", 1)[0].strip()

    header_norm = header.replace("<>", "->")
    header_norm = re.sub(r"\s+", " ", header_norm).strip()
    toks = header_norm.split()

    action = toks[0] if len(toks) > 0 else ""
    proto  = toks[1] if len(toks) > 1 else ""

    src = srcport = dst = dstport = direction = ""
    if "->" in toks:
        i = toks.index("->")
        direction = "->"
        src     = toks[2] if len(toks) > 2 else ""
        srcport = toks[3] if len(toks) > 3 else ""
        dst     = toks[i+1] if len(toks) > i+1 else ""
        dstport = toks[i+2] if len(toks) > i+2 else ""
    else:
        # best-effort
        src     = toks[2] if len(toks) > 2 else ""
        srcport = toks[3] if len(toks) > 3 else ""
        dst     = toks[4] if len(toks) > 4 else ""
        dstport = toks[5] if len(toks) > 5 else ""

    # 옵션 파싱
    opts_map = parse_options_block(options_block)

    row = {
        "sid": first(opts_map, "sid"),
        "rev": first(opts_map, "rev"),
        "gid": first(opts_map, "gid"),
        "action": action,
        "proto": proto,
        "src": src,
        "src_port": srcport,
        "direction": direction,
        "dst": dst,
        "dst_port": dstport,
        "msg": first(opts_map, "msg"),
        "classtype": first(opts_map, "classtype"),
        "priority": first(opts_map, "priority"),
        "app-layer-event": first(opts_map, "app-layer-event"),
        "reference": ";".join(opts_map.get("reference", [])) if "reference" in opts_map else "",
        "metadata": ";".join(opts_map.get("metadata", [])) if "metadata" in opts_map else "",
        "content_count": len(opts_map.get("content", []) or []),
        "pcre_count": len(opts_map.get("pcre", []) or []),
        "flow": ";".join(opts_map.get("flow", []) or []),
        "flowbits": ";".join(opts_map.get("flowbits", []) or []),
        "full_options": options_block,
        "full_rule": rule.strip(),
    }
    return row

def parse_rules(text: str, include_disabled: bool=False):
    """
    파일 전체 텍스트에서 룰 추출.
    - 기본: # 으로 시작하는 비활성 룰은 스킵
    - 옵션: include_disabled=True 이면 그런 것도 시도
    """
    text = join_continuations(text)
    rows = []

    if include_disabled:
        # 주석(#) 앞 공백 제거 후 시작이 #(space)?action ... 형태도 허용
        cand = []
        for ln in text.splitlines():
            s = ln.lstrip()
            if s.startswith("#"):
                s2 = s[1:].lstrip()
                cand.append(s2)
            else:
                cand.append(ln)
        text2 = "\n".join(cand)
        matches = list(RULE_RE.finditer(text2))
        for m in matches:
            rule = m.group(0).strip()
            r = parse_rule_line(rule)
            if r:
                rows.append(r)
    else:
        matches = list(RULE_RE.finditer(text))
        for m in matches:
            rule = m.group(0).strip()
            # 원본 라인 주석은 제외
            if rule.lstrip().startswith("#"):
                continue
            r = parse_rule_line(rule)
            if r:
                rows.append(r)

    return rows

def main():
    ap = argparse.ArgumentParser(description="Parse Suricata/Snort rules into CSV")
    ap.add_argument("--in", dest="infile", required=True, help="suricata.rules path")
    ap.add_argument("--out", dest="outfile", required=True, help="output CSV path")
    ap.add_argument("--include-disabled", action="store_true", help="also try parsing disabled (#) rules")
    args = ap.parse_args()

    text = Path(args.infile).read_text(encoding="utf-8", errors="replace")
    rows = parse_rules(text, include_disabled=args.include_disabled)

    # 컬럼 순서
    cols = [
        "sid","rev","gid","action","proto","src","src_port","direction","dst","dst_port",
        "msg","classtype","priority","app-layer-event","reference","metadata",
        "content_count","pcre_count","flow","flowbits","full_options","full_rule"
    ]

    # CSV 저장
    with open(args.outfile, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in cols})

    print(f"Parsed {len(rows)} rules -> {args.outfile}")

if __name__ == "__main__":
    main()
