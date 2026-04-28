"""Normalize SARIF URIs and infer CWE from tool rules when tags are missing."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CWE_TAG = re.compile(r"external/cwe/cwe-0*(\d{1,4})", re.I)
CWE_STR = re.compile(r"cwe[-_:\s]*(\d{1,4})", re.I)


def parse_cwes_from_tags(tags: Any) -> set[int]:
    s: set[int] = set()
    if not tags:
        return s
    for t in tags:
        t = str(t)
        m = CWE_TAG.search(t)
        if m:
            s.add(int(m.group(1)))
        for m in CWE_STR.finditer(t):
            s.add(int(m.group(1)))
    return s


def build_rule_index(run: Dict[str, Any]) -> Dict[str, Any]:
    return {
        R["id"]: R
        for R in (run.get("tool") or {}).get("driver", {}).get("rules") or []
        if R.get("id")
    }


def cwes_from_rules_and_result(
    run: Dict[str, Any], r: Dict[str, Any], rule_index: Dict[str, Any]
) -> set[int]:
    s: set[int] = set()
    p = r.get("properties") or {}
    s |= parse_cwes_from_tags(p.get("tags"))
    rid = r.get("ruleId") or ""
    if rid and rid in rule_index:
        rp = (rule_index[rid].get("properties") or {})
        s |= parse_cwes_from_tags(rp.get("tags"))
    msg = (r.get("message") or {}).get("text") or ""
    for m in CWE_STR.finditer(msg):
        s.add(int(m.group(1)))
    return s


def heuristic_cwe(rule_id: str, message: str, names: str) -> set[int]:
    """Infer CWE only when rule id / clear message theme matches — not generic words in message."""
    rid = rule_id.lower()
    msg = f"{message} {names}".lower()
    out: set[int] = set()
    if any(
        p in rid
        for p in (
            "/xxe",
            "xxe",
            "external-entity",
            "disallow-doctype",
            "documentbuilderfactory",
            "simplexml",
            "xmldocument",
            "xpath-injection",
        )
    ) or ("xml external entity" in msg or "external entity expansion" in msg):
        out.add(611)
    if any(
        p in rid
        for p in (
            "xss",
            "no-direct-response-writer",
            "unsafe-template-type",
            "template-html-does-not-escape",
            "reflected-xss",
            ".xss/",
        )
    ) or ("cross-site scripting" in msg or "xss vulnerability" in msg):
        out.add(79)
    return out


def infer_cwes(
    run: Dict[str, Any], r: Dict[str, Any], rule_index: Dict[str, Any]
) -> set[int]:
    s = cwes_from_rules_and_result(run, r, rule_index)
    if s:
        return s
    rid = str(r.get("ruleId") or "")
    msg = (r.get("message") or {}).get("text") or ""
    nm = ""
    if rid in rule_index:
        rr = rule_index[rid]
        for key in ("name", "shortDescription", "fullDescription"):
            v = rr.get(key)
            if isinstance(v, str):
                nm = v
                break
            if isinstance(v, dict) and v.get("text"):
                nm = str(v.get("text"))
                break
    s2 = heuristic_cwe(rid, msg, nm)
    return s2 if s2 else set()


def primary_location(r: Dict[str, Any]) -> Optional[Tuple[str, int]]:
    locs = r.get("locations") or []
    if not locs:
        return None
    pl = locs[0].get("physicalLocation") or {}
    al = pl.get("artifactLocation") or {}
    uri = al.get("uri") or al.get("uriBaseId")
    if uri and "{" in str(uri):
        return None
    uri = str(uri or "")
    uri = uri.split("file://")[-1].lstrip("/")
    if ":" in uri and uri.startswith("/") and "Users" not in uri[:20]:
        pass
    reg = pl.get("region") or {}
    line = reg.get("startLine")
    if not line:
        return None
    return uri, int(line)


def normalize_uri(uri: str, benchmark: str) -> str:
    """Return path relative to benchmark project (e.g. src/main/java/... or api/...)."""
    u = uri.replace("\\", "/").split("file://")[-1]
    for marker in (
        f"/{benchmark}/",
        f"{benchmark}/",
        f"/{benchmark.lower()}/",
    ):
        idx = u.replace("\\", "/").find(marker)
        if idx != -1:
            return u[idx + len(marker) :].lstrip("/")
    if "/src/main/java/" in u:
        return "src/main/java" + u.split("/src/main/java", 1)[1]
    parts = u.replace("\\", "/").split("/")
    for i, p in enumerate(parts):
        if p == benchmark:
            return "/".join(parts[i + 1 :])
    basename = parts[-1]
    if basename and "/" not in uri and "\\" not in uri:
        return basename
    return u


def load_findings(sarif_path: Path, benchmark: str) -> List[Dict[str, Any]]:
    text = sarif_path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    doc = json.loads(text)
    rows: List[Dict[str, Any]] = []
    for run in doc.get("runs") or []:
        rule_index = build_rule_index(run)
        for r in run.get("results") or []:
            ploc = primary_location(r)
            if not ploc:
                continue
            raw_uri, line = ploc
            rel = normalize_uri(raw_uri, benchmark)
            cwes = infer_cwes(run, r, rule_index)
            rows.append(
                {
                    "relpath": rel,
                    "line": line,
                    "cwes": cwes,
                    "rule_id": r.get("ruleId") or "",
                }
            )
    return rows
