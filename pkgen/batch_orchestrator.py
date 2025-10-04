#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
batch_orchestrator.py
- Warmup(샘플) → Shard 병렬 실행 → 간단 리포트
- pkgen_by_suricata_rules.py 를 여러 워커로 호출

Usage:
  python batch_orchestrator.py \
    --parsed suricata_rules_parsed.csv \
    --dst 192.168.100.80 --src 111.111.111.111 \
    --use-llm --warmup 5000 \
    --shards 9 --jobs 3 \
    --out-root outputs/full_run_20251004 \
    --max-pkts 0
"""

import argparse, os, csv, math, subprocess, sys
from pathlib import Path
from typing import List

PKGEN = "pkgen_by_suricata_rules.py"

def run_cmd(cmd: List[str]):
    print("[RUN]", " ".join(cmd), flush=True)
    proc = subprocess.Popen(cmd)
    proc.wait()
    if proc.returncode != 0:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}")

def head_csv(src_csv: Path, dst_csv: Path, n: int):
    dst_csv.parent.mkdir(parents=True, exist_ok=True)
    with src_csv.open("r", encoding="utf-8", newline="") as f_in, \
         dst_csv.open("w", encoding="utf-8", newline="") as f_out:
        r = csv.reader(f_in)
        w = csv.writer(f_out)
        header = next(r, None)
        if header: w.writerow(header)
        count = 0
        for row in r:
            if count >= n: break
            w.writerow(row)
            count += 1

def split_csv(src_csv: Path, out_dir: Path, shards: int) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    with src_csv.open("r", encoding="utf-8", newline="") as f:
        r = list(csv.reader(f))
    if not r: return []
    header, rows = r[0], r[1:]
    total = len(rows)
    per = math.ceil(total / shards)
    parts = []
    for i in range(shards):
        start = i*per
        end = min((i+1)*per, total)
        part = rows[start:end]
        if not part: break
        p = out_dir / f"part_{i+1:02d}.csv"
        with p.open("w", encoding="utf-8", newline="") as f_out:
            w = csv.writer(f_out)
            w.writerow(header)
            w.writerows(part)
        parts.append(p)
    return parts

def main():
    ap = argparse.ArgumentParser(description="Batch orchestrator for pkgen")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--parsed", help="suricata_rules_parsed.csv (권장)")
    src.add_argument("--rules", help="suricata.rules (raw)")
    ap.add_argument("--dst", required=True)
    ap.add_argument("--src", default="192.168.56.10")
    ap.add_argument("--use-llm", action="store_true")
    ap.add_argument("--warmup", type=int, default=0, help="웜업 개수 (0=스킵)")
    ap.add_argument("--shards", type=int, default=8, help="샤드 수")
    ap.add_argument("--jobs", type=int, default=2, help="동시 워커 수")
    ap.add_argument("--out-root", required=True, help="최상위 출력 루트 디렉토리")
    ap.add_argument("--max-pkts", type=int, default=0)
    args = ap.parse_args()

    out_root = Path(args.out_root)
    out_root.mkdir(parents=True, exist_ok=True)

    # 0) 경로 확인
    parsed_csv = Path(args.parsed) if args.parsed else None
    rules = Path(args.rules) if args.rules else None
    if parsed_csv and not parsed_csv.exists():
        raise FileNotFoundError(parsed_csv)
    if rules and not rules.exists():
        raise FileNotFoundError(rules)

    # 1) 웜업 (옵션)
    if args.warmup and parsed_csv:
        warm_csv = out_root / "warmup.csv"
        head_csv(parsed_csv, warm_csv, args.warmup)
        warm_out = out_root / "warmup_pcaps"
        cmd = [sys.executable, PKGEN,
               "--parsed", str(warm_csv),
               "--dst", args.dst, "--src", args.src,
               "--out", str(warm_out),
               "--count", str(args.warmup),
               "--easy-count", "0",
               "--max-pkts", str(args.max_pkts)]
        if args.use_llm: cmd.append("--use-llm")
        run_cmd(cmd)

    # 2) 샤딩
    if parsed_csv:
        shard_dir = out_root / "shards"
        parts = split_csv(parsed_csv, shard_dir, args.shards)
    else:
        # rules 모드면 샤딩 없이 동일 입력으로 병렬 돌리기(주의: 중복 생성 많음)
        shard_dir = out_root / "shards_rules"
        shard_dir.mkdir(parents=True, exist_ok=True)
        parts = [rules]  # 단일 입력

    if not parts:
        print("No shards detected; exit.")
        return

    # 3) 병렬 실행 (간단한 워커 큐)
    from queue import Queue
    from threading import Thread, Lock
    q = Queue()
    for i, p in enumerate(parts, start=1):
        q.put((i, p))
    lock = Lock()
    errors = []

    def worker():
        while not q.empty():
            try:
                idx, part = q.get_nowait()
            except Exception:
                return
            try:
                out_dir = out_root / f"pcaps_{idx:02d}"
                cmd = [sys.executable, PKGEN,
                       "--dst", args.dst, "--src", args.src,
                       "--out", str(out_dir),
                       "--count", "500000000",   # 사실상 전체
                       "--easy-count", "0",
                       "--max-pkts", str(args.max_pkts)]
                if args.use_llm: cmd.append("--use-llm")
                if parsed_csv:
                    cmd += ["--parsed", str(part)]
                else:
                    cmd += ["--rules", str(part)]
                run_cmd(cmd)
            except Exception as e:
                with lock:
                    errors.append((str(part), str(e)))
            finally:
                q.task_done()

    threads = [Thread(target=worker, daemon=True) for _ in range(args.jobs)]
    for t in threads: t.start()
    for t in threads: t.join()

    if errors:
        print("\n[WARN] 일부 샤드 실패:", len(errors))
        for p, e in errors[:10]:
            print(" -", p, "=>", e)
    else:
        print("\n[OK] 모든 샤드 완료")

    print("\n[HINT] 뒤이어 index_meta_collector.py 로 메타 CSV를 만들어 정리하세요.")
    print(f"e.g., python index_meta_collector.py --root {args.out_root} --out {args.out_root}/index.csv")

if __name__ == "__main__":
    main()
