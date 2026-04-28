#!/usr/bin/env python3
"""
Convert joern-scan text output (lines starting with ``Result:``) to SARIF 2.1.0.

Expected line shape (examples)::

  Result: 4.0 : Non-constant format string ...: api/08_StringSemantics.go:49:methodName
  Result: 5.0 : CWE-79(Cross-site Scripting): ...: 08_Foo.php:2:scope

If there are no Result lines, writes a valid SARIF with an empty ``results`` array
and a placeholder rule ``joern/empty``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Dict, List

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

# Last ``path:line:`` in the line (title may contain colons, e.g. CWE-79: ...).
# File tail: IAMeter + C/C++ Juliet-style paths
RESULT_RE = re.compile(
    r"^Result:\s*(?P<score>[\d.]+)\s*:\s*(?P<title>.*?)(?P<path>[\w/.\-]+\.(?:go|java|php|c|h|cc|cpp|cxx|hpp|hxx)):(?P<line>\d+):(?P<tail>.*)$"
)

CWE_IN_MSG = re.compile(r"CWE[-\s]?(\d{1,4})", re.IGNORECASE)


def _rule_id_from_title(title: str) -> str:
    h = hashlib.sha256(title.encode("utf-8", errors="replace")).hexdigest()[:12]
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", title.strip())[:48].strip("-").lower()
    return f"joern/{slug or 'rule'}-{h}"


def _level_for_score(score: str) -> str:
    try:
        s = float(score)
    except ValueError:
        return "warning"
    if s >= 7.0:
        return "error"
    if s >= 4.0:
        return "warning"
    return "note"


def _cwe_properties(message: str) -> Dict[str, Any]:
    props: Dict[str, Any] = {"tags": ["security"]}
    m = CWE_IN_MSG.search(message)
    if m:
        n = m.group(1)
        props["tags"].append(
            f"external/cwe/cwe-{int(n):03d}" if n.isdigit() else f"external/cwe/cwe-{n}"
        )
    return props


def parse_results(text: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        m = RESULT_RE.match(line)
        if not m:
            continue
        path = m.group("path").replace("\\", "/")
        line_no = int(m.group("line"))
        title = m.group("title").strip()
        score = m.group("score")
        rule_id = _rule_id_from_title(title)
        message = f"{title} (score {score})"
        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "message": {"text": message},
            "level": _level_for_score(score),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": line_no},
                    }
                }
            ],
            "properties": _cwe_properties(title + " " + m.group("tail")),
        }
        out.append(result)
    return out


def _driver_rules_for_results(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: set[str] = set()
    rules: List[Dict[str, Any]] = []
    for r in results:
        rid = r["ruleId"]
        if rid in seen:
            continue
        seen.add(rid)
        msg = (r.get("message") or {}).get("text") or rid
        rules.append(
            {
                "id": rid,
                "shortDescription": {"text": msg[:300]},
            }
        )
    return rules


def convert_file(txt_path: Path, sarif_path: Path) -> int:
    text = txt_path.read_text(encoding="utf-8", errors="replace")
    results = parse_results(text)
    if results:
        driver_rules = _driver_rules_for_results(results)
    else:
        driver_rules = [
            {
                "id": "joern/empty",
                "shortDescription": {
                    "text": "No Result: lines in joern-scan log (0 query matches in text)"
                },
            }
        ]
    out_doc: Dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Joern",
                        "semanticVersion": "joern-scan",
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }
    sarif_path.write_text(
        json.dumps(out_doc, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(results)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--text",
        type=Path,
        help="Path to joern-scan.txt",
    )
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        help="Output SARIF path",
    )
    ap.add_argument(
        "--root",
        type=Path,
        help="Project root: convert IAMeter_*/joern-scan.txt -> IAMeter_*/joern-scan.sarif for each",
    )
    args = ap.parse_args()
    if args.root:
        root = args.root.resolve()
        for sub in ("IAMeter_Go", "IAMeter_Java", "IAMeter_PHP"):
            t = root / sub / "joern-scan.txt"
            o = root / sub / "joern-scan.sarif"
            if not t.is_file():
                print(f"skip (no {t})")
                continue
            n = convert_file(t, o)
            print(f"Wrote {o} ({n} results)")
        return 0
    if not args.text or not args.out:
        ap.error("use --text and -o, or use --root <repo>")
    n = convert_file(args.text.resolve(), args.out.resolve())
    print(f"Wrote {args.out} ({n} results)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
