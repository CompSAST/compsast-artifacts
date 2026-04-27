#!/usr/bin/env python3
"""
Merge several PVS-Studio JSON reports (version 3, ``warnings`` array) into one file.
Use after running the Java analyzer once per source file to combine results.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List, Tuple


def _warn_key(w: dict[str, Any]) -> Tuple:
    code = w.get("code") or ""
    if code == "Renew":
        return ("renew",)
    pl = (w.get("positions") or [{}])[0]
    f = (pl.get("file") or "").replace("\\", "/")
    line = int(pl.get("line") or 0)
    return (code, f, line, (w.get("message") or "")[:120])


def merge_files(paths: List[Path]) -> dict[str, Any]:
    out_warnings: list[dict[str, Any]] = []
    seen: set[Tuple] = set()
    for p in paths:
        if not p.is_file():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except (OSError, json.JSONDecodeError):
            continue
        for w in data.get("warnings") or []:
            k = _warn_key(w)
            if k in seen:
                continue
            seen.add(k)
            out_warnings.append(w)
    return {"version": 3, "warnings": out_warnings}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "inputs",
        nargs="*",
        type=Path,
        help="PVS JSON report files. Optional if --from-dir is set.",
    )
    ap.add_argument(
        "--from-dir",
        type=Path,
        metavar="DIR",
        help="Load all *.json in this directory.",
    )
    ap.add_argument(
        "-o",
        "--output",
        type=Path,
        required=True,
        help="Combined JSON path",
    )
    args = ap.parse_args()
    paths: list[Path] = list(args.inputs)
    if args.from_dir:
        if not args.from_dir.is_dir():
            ap.error(f"not a directory: {args.from_dir}")
        paths = sorted(args.from_dir.glob("*.json"))
    if not paths:
        ap.error("no input JSON files (pass files and/or --from-dir)")

    merged = merge_files(paths)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Wrote {args.output} ({len(merged.get('warnings', []))} warnings)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
