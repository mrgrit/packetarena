#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
index_meta_collector.py
- outputs/*/*.pcap 과 log/llm/*.qna 를 스캔해서 메타 CSV 생성

Usage:
  python index_meta_collector.py --root outputs/full_run_20251004 --out outputs/full_run_20251004/index.csv
"""

import argparse, re, csv
from pathlib import Path
from typing import Dict, Any

# pcap 파일명 패턴:
# <sid>__<msg>__SRC_<src>__DST_<dst>__<group>__by_<model>__v<rev>__L<length>.pcap
PCAP_RE = re.compile(
    r'^(?P<sid>[^_]+)__'
    r'(?P<msg>[^_]+)__(?:SRC_)(?P<src>[^_]+)__(?:DST_)(?P<dst>[^_]+)__'
    r'(?P<group>[^_]+)__(?:by_)'
    r'(?P<model>[^_]+)'
    r'(?:__v(?P<rev>\d+))?'
    r'(?:__L(?P<length>\d+))?\.pcap$'
)

def parse_qna(qna_path: Path) -> Dict[str, Any]:
    meta = {"LLM_STATUS":"", "PACKET_COUNT":"", "FILE":"", "RULE_REV":"", "RULE_GID":"", "MODEL":""}
    try:
        with qna_path.open("r", encoding="utf-8") as f:
            for line in f:
                line=line.strip()
                if line.startswith("MODEL:"): meta["MODEL"]=line.split(":",1)[1].strip()
                elif line.startswith("LLM_STATUS:"): meta["LLM_STATUS"]=line.split(":",1)[1].strip()
                elif line.startswith("PACKET_COUNT:"): meta["PACKET_COUNT"]=line.split(":",1)[1].strip()
                elif line.startswith("FILE:"): meta["FILE"]=line.split(":",1)[1].strip()
                elif line.startswith("RULE_REV:"): meta["RULE_REV"]=line.split(":",1)[1].strip()
                elif line.startswith("RULE_GID:"): meta["RULE_GID"]=line.split(":",1)[1].strip()
    except Exception:
        pass
    return meta

def main():
    ap = argparse.ArgumentParser(description="Collect pcap/qna meta into CSV")
    ap.add_argument("--root", required=True, help="outputs 루트 (pcaps_* 디렉토리들이 있는 상위)")
    ap.add_argument("--out", required=True, help="결과 CSV 경로")
    ap.add_argument("--qna", default="log/llm", help="QnA 로그 루트 (기본: log/llm)")
    args = ap.parse_args()

    root = Path(args.root)
    out_csv = Path(args.out)
    qna_root = Path(args.qna)

    rows = []
    # 1) PCAP 스캔
    for pcap in root.rglob("*.pcap"):
        m = PCAP_RE.match(pcap.name)
        if not m:
            # 네이밍 규칙과 다른 파일은 스킵
            continue
        d = m.groupdict()
        sid = d.get("sid","")
        model = d.get("model","")
        # 2) QNA 매칭: <sid>__by_<model>.qna
        qna_path = qna_root / f"{sid}__by_{model}.qna"
        qna_meta = parse_qna(qna_path) if qna_path.exists() else {}

        row = {
            "SID": sid,
            "MSG_SLUG": d.get("msg",""),
            "SRC": d.get("src","").replace("-", "."),
            "DST": d.get("dst","").replace("-", "."),
            "GROUP_ID": d.get("group",""),
            "MODEL": model,
            "REV": d.get("rev",""),
            "LEN": d.get("length",""),
            "FILE": str(pcap),
            "QNA_STATUS": qna_meta.get("LLM_STATUS",""),
            "QNA_PACKET_COUNT": qna_meta.get("PACKET_COUNT",""),
            "QNA_FILE": qna_meta.get("FILE",""),
            "QNA_RULE_REV": qna_meta.get("RULE_REV",""),
            "QNA_RULE_GID": qna_meta.get("RULE_GID","")
        }
        rows.append(row)

    # 3) CSV 출력
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    cols = ["SID","MSG_SLUG","SRC","DST","GROUP_ID","MODEL","REV","LEN","FILE",
            "QNA_STATUS","QNA_PACKET_COUNT","QNA_FILE","QNA_RULE_REV","QNA_RULE_GID"]
    with out_csv.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] Indexed {len(rows)} pcaps -> {out_csv}")

if __name__ == "__main__":
    main()
