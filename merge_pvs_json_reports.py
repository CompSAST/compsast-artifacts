#!/usr/bin/env python3
"""
Merge several PVS-Studio JSON reports (version 3, ``warnings`` array) into one file.
Use after running the Java analyzer once per source file to combine results.

C/C++ ``pvs-studio`` with ``--new-output-format=yes`` may append one JSON object per
line (NDJSON) into ``--output-file``; that form is also accepted per input file.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, List, Optional, Tuple


def _warnings_from_parsed(data: Any) -> Optional[List[dict[str, Any]]]:
    if isinstance(data, dict) and "warnings" in data:
        w = data.get("warnings")
        if isinstance(w, list):
            return [x for x in w if isinstance(x, dict)]
    if isinstance(data, list) and data and isinstance(data[0], dict):
        return [x for x in data if isinstance(x, dict)]
    return None


def load_warnings_from_file(path: Path) -> List[dict[str, Any]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return []
    if not text:
        return []
    try:
        data = json.loads(text)
        w = _warnings_from_parsed(data)
        if w is not None:
            return w
    except json.JSONDecodeError:
        pass
    out: List[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and (
            "code" in obj or "positions" in obj or "message" in obj
        ):
            out.append(obj)
    return out


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
        for w in load_warnings_from_file(p):
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
