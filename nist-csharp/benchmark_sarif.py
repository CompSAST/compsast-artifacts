#!/usr/bin/env python3
"""
Score SARIF findings against the NIST Juliet C# test suite.

The script builds an approximate Juliet ground truth from generated testcase
headers, C# Bad/Good method regions, and concrete FLAW/FIX comment lines.
It emits:
  - summary.csv: overall TP/FP/TN/FN and derived metrics
  - by_cwe.csv: TP/FP/TN/FN and metrics per CWE
  - points.csv: one row per evaluated Juliet FLAW/FIX point
  - regions.csv: method ranges used as context for matching
  - findings.csv: one row per SARIF finding with its classification context
  - dojo_<tool>.json: optional DefectDojo Generic Findings Import payload
"""

import argparse
import csv
import datetime
import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


METHOD_RE = re.compile(
    r"^\s*(?:public|private|protected|internal)\s+"
    r"(?:(?:static|override|virtual|sealed|async|new)\s+)*"
    r"(?:[\w<>\[\],\s]+\s+)"
    r"(?P<name>[A-Za-z_]\w*)\s*\([^;]*\)\s*$"
)

HEADER_FIELD_RE = re.compile(r"^\s*\*?\s*(?P<key>[A-Za-z ]+):\s*(?P<value>.+?)\s*$")
CWE_RE = re.compile(r"\bCWE[-_ ]?(?P<num>\d+)\b", re.IGNORECASE)
FILENAME_CWE_RE = re.compile(r"\bCWE(?P<num>\d+)_(?P<name>[^/\\]+?)(?:__|/|\\)")
FLOW_RE = re.compile(r"_(?P<flow>\d{2})(?:_[A-Za-z0-9]+|[a-z])?\.cs$", re.IGNORECASE)


@dataclass
class Finding:
    tool: str
    rule_id: str
    message: str
    file: str
    line: int
    end_line: int
    snippet: str
    actual_cwe: Optional[str] = None
    region_id: str = ""
    region_type: str = "unknown"
    point_id: str = ""
    point_kind: str = ""
    expected_cwe: str = ""
    classification: str = "unknown"


@dataclass
class Region:
    region_id: str
    testcase_id: str
    file: str
    method: str
    region_type: str
    start_line: int
    end_line: int
    cwe_id: str
    cwe_name: str
    flow_variant: str
    template_file: str
    findings: List[Finding] = field(default_factory=list)


@dataclass
class ExpectedPoint:
    point_id: str
    testcase_id: str
    file: str
    line: int
    method: str
    region_id: str
    region_type: str
    point_kind: str
    comment: str
    cwe_id: str
    cwe_name: str
    flow_variant: str
    template_file: str
    findings: List[Finding] = field(default_factory=list)
    status: str = "UNSEEN"


def normalize_rel_path(path: str, src_root: Path) -> str:
    """Normalize SARIF and filesystem paths to paths relative to src/testcases."""
    cleaned = path.replace("\\", "/")
    cleaned = re.sub(r"^[a-zA-Z]:", "", cleaned)
    cleaned = cleaned.lstrip("/")

    marker = "src/testcases/"
    if marker in cleaned:
        cleaned = cleaned.split(marker, 1)[1]

    candidate = Path(cleaned)
    if candidate.is_absolute():
        try:
            return candidate.relative_to(src_root).as_posix()
        except ValueError:
            return candidate.as_posix().lstrip("/")

    return cleaned


def safe_div(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def metrics(counts: Dict[str, int]) -> Dict[str, float]:
    tp = counts.get("TP", 0)
    fp = counts.get("FP", 0)
    tn = counts.get("TN", 0)
    fn = counts.get("FN", 0)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    f1 = round(2 * precision * recall / (precision + recall), 6) if precision + recall else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "f1": f1,
    }


def parse_header(lines: Sequence[str], rel_path: str) -> Dict[str, str]:
    """Extract Juliet metadata from the generated header comment."""
    meta: Dict[str, str] = {}
    for line in lines[:80]:
        match = HEADER_FIELD_RE.match(line)
        if not match:
            continue

        key = match.group("key").strip().lower().replace(" ", "_")
        value = match.group("value").strip()
        meta[key] = value

        if key == "cwe":
            parts = value.split(maxsplit=1)
            if parts and parts[0].isdigit():
                meta["cwe_id"] = f"CWE{parts[0]}"
                meta["cwe_name"] = parts[1] if len(parts) > 1 else ""

    # Filename is still the best fallback for generated files with unusual headers.
    if "cwe_id" not in meta:
        match = FILENAME_CWE_RE.search(rel_path)
        if match:
            meta["cwe_id"] = f"CWE{match.group('num')}"
            meta["cwe_name"] = match.group("name").replace("_", " ")

    if "flow_variant" not in meta:
        match = FLOW_RE.search(rel_path)
        if match:
            meta["flow_variant"] = match.group("flow")

    return meta


def strip_string_literals(line: str) -> str:
    """Remove simple string and char literals before brace counting."""
    line = re.sub(r'@"(?:""|[^"])*"', '""', line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])+'", "''", line)
    return line


def count_braces(line: str) -> int:
    stripped = strip_string_literals(line)
    return stripped.count("{") - stripped.count("}")


def classify_method(method_name: str, rel_path: str) -> Optional[str]:
    """Map Juliet method/file naming conventions to bad/good regions."""
    name = method_name.lower()
    lower_path = rel_path.lower()

    # The generated Good() method is usually only a dispatcher that calls
    # GoodG2B/GoodB2G variants. Counting it as a separate TN would inflate
    # specificity without adding another meaningful testcase path.
    if name == "good":
        return None

    if lower_path.endswith("_bad.cs"):
        return "bad"
    if "_good" in lower_path:
        return "good"

    if name.startswith("bad"):
        return "bad"
    if name.startswith("good"):
        return "good"

    return None


def testcase_id_from_path(rel_path: str) -> str:
    """Group split Juliet files into a stable testcase id."""
    stem = Path(rel_path).stem
    stem = re.sub(r"_(bad|goodG2B|goodB2G|base)$", "", stem, flags=re.IGNORECASE)
    stem = re.sub(r"_(\d{2})[a-z]$", r"_\1", stem, flags=re.IGNORECASE)
    return stem


def find_method_regions(path: Path, src_root: Path) -> List[Region]:
    rel_path = path.relative_to(src_root).as_posix()
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    meta = parse_header(lines, rel_path)
    cwe_id = meta.get("cwe_id", "")
    cwe_name = meta.get("cwe_name", "")
    flow_variant = meta.get("flow_variant", "")
    template_file = meta.get("template_file", "")
    testcase_id = testcase_id_from_path(rel_path)

    regions: List[Region] = []
    pending_method: Optional[Tuple[str, int, str]] = None
    active_method: Optional[Tuple[str, int, str, int]] = None

    for index, line in enumerate(lines, start=1):
        if active_method:
            name, start_line, region_type, depth = active_method
            depth += count_braces(line)
            if depth <= 0:
                region_id = f"{rel_path}:{name}:{start_line}-{index}"
                regions.append(
                    Region(
                        region_id=region_id,
                        testcase_id=testcase_id,
                        file=rel_path,
                        method=name,
                        region_type=region_type,
                        start_line=start_line,
                        end_line=index,
                        cwe_id=cwe_id,
                        cwe_name=cwe_name,
                        flow_variant=flow_variant,
                        template_file=template_file,
                    )
                )
                active_method = None
            else:
                active_method = (name, start_line, region_type, depth)
            continue

        method_match = METHOD_RE.match(line)
        if method_match:
            method_name = method_match.group("name")
            region_type = classify_method(method_name, rel_path)
            if region_type:
                pending_method = (method_name, index, region_type)

        if pending_method and "{" in line:
            method_name, start_line, region_type = pending_method
            depth = count_braces(line)
            if depth <= 0:
                depth = 1
            active_method = (method_name, start_line, region_type, depth)
            pending_method = None

    return regions


def iter_cs_files(src_root: Path) -> Iterable[Path]:
    for path in src_root.rglob("*.cs"):
        if path.is_file():
            yield path


def load_rule_cwe_map(path: Optional[Path]) -> Dict[str, str]:
    if not path:
        return {}

    rule_map: Dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rule_id = (row.get("rule_id") or "").strip()
            cwe = normalize_cwe_id(row.get("cwe") or row.get("cwe_id") or "")
            if rule_id and cwe:
                rule_map[rule_id] = cwe
    return rule_map


def normalize_cwe_id(value: str) -> Optional[str]:
    value = (value or "").strip().upper().replace("-", "")
    if value.isdigit():
        return f"CWE{int(value)}"

    match = CWE_RE.search(value)
    if match:
        return f"CWE{int(match.group('num'))}"

    return None


def find_cwe(value: str) -> Optional[str]:
    match = CWE_RE.search(value or "")
    if match:
        return f"CWE{int(match.group('num'))}"
    return None


def sarif_rule_cwe_map(run: Dict[str, object]) -> Dict[str, str]:
    """Extract rule -> CWE mappings from SARIF rule metadata.

    PVS-Studio stores CWE information in rule properties tags such as
    external/cwe/cwe-571, while individual results only contain ruleId=V3022.
    """
    rule_map: Dict[str, str] = {}
    tool = run.get("tool") if isinstance(run, dict) else {}
    driver = tool.get("driver") if isinstance(tool, dict) else {}
    rules = driver.get("rules", []) if isinstance(driver, dict) else []

    for rule in rules:
        if not isinstance(rule, dict):
            continue

        rule_id = str(rule.get("id") or "").strip()
        if not rule_id:
            continue

        cwe = find_cwe(rule_id) or find_cwe(str(rule.get("name") or ""))
        properties = rule.get("properties") or {}
        if isinstance(properties, dict):
            tags = properties.get("tags") or []
            for tag in tags:
                cwe = cwe or find_cwe(str(tag))
            for value in properties.values():
                if cwe:
                    break
                if isinstance(value, str):
                    cwe = find_cwe(value)

        if cwe:
            rule_map[rule_id] = cwe

    return rule_map


def infer_cwe_from_finding(rule_id: str, message: str, rule_map: Dict[str, str]) -> Optional[str]:
    if rule_id in rule_map:
        return rule_map[rule_id]

    return find_cwe(rule_id) or find_cwe(message)


def load_sarif(path: Path, tool: str, src_root: Path, rule_map: Dict[str, str]) -> List[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    findings: List[Finding] = []
    for run in data.get("runs", []):
        run_rule_map = sarif_rule_cwe_map(run)
        run_rule_map.update(rule_map)
        for result in run.get("results", []):
            locations = result.get("locations") or []
            if not locations:
                continue

            physical = locations[0].get("physicalLocation") or {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            uri = artifact.get("uri") or ""
            line = int(region.get("startLine") or 0)
            end_line = int(region.get("endLine") or line)
            rule_id = result.get("ruleId") or ""
            message = (result.get("message") or {}).get("text") or ""
            snippet = (region.get("snippet") or {}).get("text") or ""
            rel_file = normalize_rel_path(uri, src_root)

            findings.append(
                Finding(
                    tool=tool,
                    rule_id=rule_id,
                    message=message,
                    file=rel_file,
                    line=line,
                    end_line=end_line,
                    snippet=snippet,
                    actual_cwe=infer_cwe_from_finding(rule_id, message, run_rule_map),
                )
            )
    return findings


def build_regions(src_root: Path) -> List[Region]:
    regions: List[Region] = []
    for path in iter_cs_files(src_root):
        regions.extend(find_method_regions(path, src_root))
    return regions


def extract_comment_text(line: str) -> str:
    """Keep the marker line readable in CSV/DefectDojo output."""
    return line.strip().strip("/").strip("*").strip()


def build_expected_points(src_root: Path, regions: List[Region]) -> List[ExpectedPoint]:
    """Build line-aware Juliet expectations from FLAW/FIX comments.

    Vulnerable points are FLAW/POTENTIAL FLAW comments inside Bad regions.
    Safe points are FIX comments and good-path FLAW decoys inside Good regions.
    """
    lines_by_file: Dict[str, List[str]] = {}
    points: List[ExpectedPoint] = []

    for region in regions:
        if region.file not in lines_by_file:
            path = src_root / region.file
            lines_by_file[region.file] = path.read_text(encoding="utf-8", errors="replace").splitlines()

        lines = lines_by_file[region.file]
        for line_no in range(region.start_line, region.end_line + 1):
            text = lines[line_no - 1] if line_no - 1 < len(lines) else ""
            has_flaw = "FLAW" in text and "FIX" not in text
            has_fix = "FIX" in text
            point_kind: Optional[str] = None

            if region.region_type == "bad" and has_flaw:
                point_kind = "vulnerable"
            elif region.region_type == "good" and (has_fix or has_flaw):
                # Good paths can still contain "POTENTIAL FLAW" sink comments.
                # In those paths the dataflow is safe, so these are decoy safe points.
                point_kind = "safe"

            if not point_kind:
                continue

            point_id = f"{region.file}:{line_no}:{point_kind}"
            points.append(
                ExpectedPoint(
                    point_id=point_id,
                    testcase_id=region.testcase_id,
                    file=region.file,
                    line=line_no,
                    method=region.method,
                    region_id=region.region_id,
                    region_type=region.region_type,
                    point_kind=point_kind,
                    comment=extract_comment_text(text),
                    cwe_id=region.cwe_id,
                    cwe_name=region.cwe_name,
                    flow_variant=region.flow_variant,
                    template_file=region.template_file,
                )
            )

    return points


def find_region_for_finding(finding: Finding, regions_by_file: Dict[str, List[Region]], window: int) -> Optional[Region]:
    candidates = regions_by_file.get(finding.file, [])
    for region in candidates:
        if region.start_line <= finding.line <= region.end_line:
            return region

    if window <= 0:
        return None

    # Some tools report a nearby call or declaration instead of the exact sink line.
    for region in candidates:
        if region.start_line - window <= finding.line <= region.end_line + window:
            return region

    return None


def is_relevant(finding: Finding, cwe_id: str, cwe_aware: bool) -> bool:
    if not cwe_aware:
        return True
    if not finding.actual_cwe:
        return False
    return finding.actual_cwe == cwe_id


def find_nearest_point(
    finding: Finding,
    points_by_file: Dict[str, List[ExpectedPoint]],
    point_kind: str,
    window: int,
) -> Optional[ExpectedPoint]:
    candidates = points_by_file.get(finding.file, [])
    matching = [
        point
        for point in candidates
        if point.point_kind == point_kind and abs(point.line - finding.line) <= window
    ]
    if not matching:
        return None
    return min(matching, key=lambda point: abs(point.line - finding.line))


def classify(regions: List[Region], points: List[ExpectedPoint], findings: List[Finding], cwe_aware: bool, window: int) -> None:
    regions_by_file: Dict[str, List[Region]] = {}
    for region in regions:
        regions_by_file.setdefault(region.file, []).append(region)

    points_by_file: Dict[str, List[ExpectedPoint]] = {}
    for point in points:
        points_by_file.setdefault(point.file, []).append(point)

    for finding in findings:
        region = find_region_for_finding(finding, regions_by_file, window)
        if region:
            finding.region_id = region.region_id
            finding.region_type = region.region_type
            finding.expected_cwe = region.cwe_id

        vulnerable_point = find_nearest_point(finding, points_by_file, "vulnerable", window)
        if vulnerable_point:
            finding.expected_cwe = vulnerable_point.cwe_id
            if not is_relevant(finding, vulnerable_point.cwe_id, cwe_aware):
                finding.classification = "out_of_scope"
                continue
            vulnerable_point.findings.append(finding)
            finding.point_id = vulnerable_point.point_id
            finding.point_kind = vulnerable_point.point_kind
            finding.region_id = vulnerable_point.region_id
            finding.region_type = vulnerable_point.region_type
            finding.classification = "matched_tp"
            continue

        safe_point = find_nearest_point(finding, points_by_file, "safe", window)
        if safe_point:
            finding.expected_cwe = safe_point.cwe_id
            if not is_relevant(finding, safe_point.cwe_id, cwe_aware):
                finding.classification = "out_of_scope"
                continue
            safe_point.findings.append(finding)
            finding.point_id = safe_point.point_id
            finding.point_kind = safe_point.point_kind
            finding.region_id = safe_point.region_id
            finding.region_type = safe_point.region_type
            finding.classification = "matched_fp"
            continue

        if region:
            if cwe_aware and not is_relevant(finding, region.cwe_id, cwe_aware=True):
                finding.classification = "out_of_scope"
            else:
                # A finding that does not point at an expected Juliet flaw line
                # is noise for line-aware scoring.
                finding.classification = "unmatched_fp"
                region.findings.append(finding)
        else:
            finding.classification = "unknown"

    for point in points:
        if point.point_kind == "vulnerable":
            point.status = "TP" if point.findings else "FN"
        else:
            point.status = "FP" if point.findings else "TN"


def count_statuses(points: Iterable[ExpectedPoint], findings: Iterable[Finding]) -> Dict[str, int]:
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}
    for point in points:
        if point.status in counts:
            counts[point.status] += 1

    # Unmatched findings are false positives because they do not identify an
    # expected Juliet vulnerable line. Safe-point FPs were already counted above.
    counts["FP"] += sum(1 for finding in findings if finding.classification == "unmatched_fp")
    return counts


def write_csv(path: Path, fieldnames: Sequence[str], rows: Iterable[Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_summary(out_dir: Path, tool: str, points: List[ExpectedPoint], findings: List[Finding]) -> None:
    counts = count_statuses(points, findings)
    summary_metrics = metrics(counts)
    row = {
        "tool": tool,
        "tp": counts["TP"],
        "fp": counts["FP"],
        "tn": counts["TN"],
        "fn": counts["FN"],
        **summary_metrics,
        "total_vulnerable_points": sum(1 for point in points if point.point_kind == "vulnerable"),
        "total_safe_points": sum(1 for point in points if point.point_kind == "safe"),
        "total_findings": len(findings),
        "unmatched_fp_findings": sum(1 for f in findings if f.classification == "unmatched_fp"),
        "unknown_findings": sum(1 for f in findings if f.classification == "unknown"),
        "out_of_scope_findings": sum(1 for f in findings if f.classification == "out_of_scope"),
    }
    fields = list(row.keys())
    write_csv(out_dir / f"{tool}_summary.csv", fields, [row])


def write_by_cwe(out_dir: Path, tool: str, points: List[ExpectedPoint], findings: List[Finding]) -> None:
    rows = []
    cwes = sorted({point.cwe_id for point in points if point.cwe_id})
    for cwe in cwes:
        cwe_points = [point for point in points if point.cwe_id == cwe]
        cwe_findings = [finding for finding in findings if finding.expected_cwe == cwe]
        counts = count_statuses(cwe_points, cwe_findings)
        first = cwe_points[0]
        row = {
            "tool": tool,
            "cwe_id": cwe,
            "cwe_name": first.cwe_name,
            "tp": counts["TP"],
            "fp": counts["FP"],
            "tn": counts["TN"],
            "fn": counts["FN"],
            **metrics(counts),
            "total_vulnerable_points": sum(1 for point in cwe_points if point.point_kind == "vulnerable"),
            "total_safe_points": sum(1 for point in cwe_points if point.point_kind == "safe"),
            "total_findings": len(cwe_findings),
            "unmatched_fp_findings": sum(1 for f in cwe_findings if f.classification == "unmatched_fp"),
            "unknown_findings": sum(1 for f in cwe_findings if f.classification == "unknown"),
            "out_of_scope_findings": sum(1 for f in cwe_findings if f.classification == "out_of_scope"),
        }
        rows.append(row)

    fields = [
        "tool",
        "cwe_id",
        "cwe_name",
        "tp",
        "fp",
        "tn",
        "fn",
        "precision",
        "recall",
        "specificity",
        "f1",
        "total_vulnerable_points",
        "total_safe_points",
        "total_findings",
        "unmatched_fp_findings",
        "unknown_findings",
        "out_of_scope_findings",
    ]
    write_csv(out_dir / f"{tool}_by_cwe.csv", fields, rows)


def write_points(out_dir: Path, tool: str, points: List[ExpectedPoint]) -> None:
    fields = [
        "tool",
        "cwe_id",
        "cwe_name",
        "testcase_id",
        "file",
        "line",
        "method",
        "region_type",
        "point_kind",
        "comment",
        "flow_variant",
        "template_file",
        "status",
        "matched_findings",
        "matched_rule_ids",
    ]
    rows = []
    for point in points:
        rows.append(
            {
                "tool": tool,
                "cwe_id": point.cwe_id,
                "cwe_name": point.cwe_name,
                "testcase_id": point.testcase_id,
                "file": point.file,
                "line": point.line,
                "method": point.method,
                "region_type": point.region_type,
                "point_kind": point.point_kind,
                "comment": point.comment,
                "flow_variant": point.flow_variant,
                "template_file": point.template_file,
                "status": point.status,
                "matched_findings": len(point.findings),
                "matched_rule_ids": ";".join(sorted({finding.rule_id for finding in point.findings})),
            }
        )
    write_csv(out_dir / f"{tool}_points.csv", fields, rows)


def write_regions(out_dir: Path, tool: str, regions: List[Region]) -> None:
    fields = [
        "tool",
        "cwe_id",
        "cwe_name",
        "testcase_id",
        "file",
        "method",
        "region_type",
        "start_line",
        "end_line",
        "flow_variant",
        "template_file",
    ]
    rows = []
    for region in regions:
        rows.append(
            {
                "tool": tool,
                "cwe_id": region.cwe_id,
                "cwe_name": region.cwe_name,
                "testcase_id": region.testcase_id,
                "file": region.file,
                "method": region.method,
                "region_type": region.region_type,
                "start_line": region.start_line,
                "end_line": region.end_line,
                "flow_variant": region.flow_variant,
                "template_file": region.template_file,
            }
        )
    write_csv(out_dir / f"{tool}_regions.csv", fields, rows)


def write_findings(out_dir: Path, tool: str, findings: List[Finding]) -> None:
    fields = [
        "tool",
        "file",
        "line",
        "end_line",
        "rule_id",
        "actual_cwe",
        "expected_cwe",
        "region_id",
        "region_type",
        "point_id",
        "point_kind",
        "classification",
        "message",
        "snippet",
    ]
    rows = []
    for finding in findings:
        rows.append(
            {
                "tool": tool,
                "file": finding.file,
                "line": finding.line,
                "end_line": finding.end_line,
                "rule_id": finding.rule_id,
                "actual_cwe": finding.actual_cwe or "",
                "expected_cwe": finding.expected_cwe,
                "region_id": finding.region_id,
                "region_type": finding.region_type,
                "point_id": finding.point_id,
                "point_kind": finding.point_kind,
                "classification": finding.classification,
                "message": finding.message,
                "snippet": finding.snippet,
            }
        )
    write_csv(out_dir / f"{tool}_findings.csv", fields, rows)


def cwe_number(cwe_id: str) -> Optional[int]:
    match = CWE_RE.search(cwe_id)
    return int(match.group("num")) if match else None


def stable_id(tool: str, point: ExpectedPoint) -> str:
    key = f"{tool}:{point.point_id}:{point.status}"
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"juliet-benchmark:{tool}:{digest}"


def dojo_severity(status: str) -> str:
    return {
        "FN": "High",
        "FP": "Medium",
        "TP": "Info",
        "TN": "Info",
    }.get(status, "Info")


def dojo_active(status: str) -> bool:
    # Correct classifications are useful dashboard facts, not active issues.
    return status in {"FN", "FP"}


def make_dojo_payload(tool: str, points: List[ExpectedPoint], include_statuses: Sequence[str]) -> Dict[str, object]:
    include = {status.upper() for status in include_statuses}
    today = datetime.date.today().isoformat()
    findings = []
    for point in points:
        if point.status not in include:
            continue

        cwe_num = cwe_number(point.cwe_id)
        title = f"{point.status}: {point.cwe_id} {point.cwe_name} at line {point.line}"
        description = (
            f"Juliet C# benchmark classification: {point.status}\n\n"
            f"Tool: {tool}\n"
            f"Point kind: {point.point_kind}\n"
            f"Region type: {point.region_type}\n"
            f"Method: {point.method}\n"
            f"Testcase: {point.testcase_id}\n"
            f"Expected CWE: {point.cwe_id} {point.cwe_name}\n"
            f"Flow variant: {point.flow_variant}\n"
            f"Template: {point.template_file}\n"
            f"Juliet marker: {point.comment}\n"
            f"Matched findings: {len(point.findings)}\n"
            f"Matched rules: {', '.join(sorted({f.rule_id for f in point.findings})) or 'none'}"
        )
        findings.append(
            {
                "title": title,
                "severity": dojo_severity(point.status),
                "description": description,
                "date": today,
                "cwe": cwe_num,
                "file_path": f"src/testcases/{point.file}",
                "line": point.line,
                "active": dojo_active(point.status),
                "verified": True,
                "static_finding": True,
                "dynamic_finding": False,
                "unique_id_from_tool": stable_id(tool, point),
                "vuln_id_from_tool": f"{point.testcase_id}:{point.line}:{point.status}",
                "tags": [
                    "benchmark:juliet-csharp",
                    f"tool:{tool}",
                    f"classification:{point.status.lower()}",
                    f"cwe:{point.cwe_id}",
                    f"point:{point.point_kind}",
                    f"region:{point.region_type}",
                    f"flow:{point.flow_variant or 'unknown'}",
                ],
            }
        )

    return {
        "name": f"Juliet CSharp Benchmark - {tool}",
        "type": "Juliet Benchmark",
        "findings": findings,
    }


def write_dojo(out_dir: Path, tool: str, points: List[ExpectedPoint], include_statuses: Sequence[str]) -> None:
    payload = make_dojo_payload(tool, points, include_statuses)
    path = out_dir / f"dojo_{tool}.json"
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score SARIF findings against Juliet C# FLAW/FIX lines.")
    parser.add_argument("--src", default="src/testcases", help="Path to Juliet C# testcases.")
    parser.add_argument("--sarif", required=True, help="SARIF report to score.")
    parser.add_argument("--tool", help="Tool name. Defaults to the SARIF filename stem.")
    parser.add_argument("--out-dir", default="results", help="Directory for generated CSV/JSON reports.")
    parser.add_argument("--line-window", type=int, default=5, help="Allow findings this many lines away from a FLAW/FIX point.")
    parser.add_argument(
        "--cwe-aware",
        dest="cwe_aware",
        action="store_true",
        default=True,
        help="Only match findings whose CWE equals the testcase CWE. Enabled by default.",
    )
    parser.add_argument(
        "--no-cwe-aware",
        dest="cwe_aware",
        action="store_false",
        help="Use the legacy line-only matching mode and ignore finding CWE.",
    )
    parser.add_argument("--rule-cwe-map", help="CSV mapping with columns rule_id,cwe.")
    parser.add_argument("--emit-defectdojo", action="store_true", help="Emit DefectDojo Generic Findings Import JSON.")
    parser.add_argument(
        "--dojo-include",
        default="FP,FN",
        help=(
            "Comma-separated statuses to include in DefectDojo JSON. "
            "Defaults to actionable benchmark misses/noise; use TP,FP,TN,FN for a full matrix payload."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    src_root = Path(args.src).resolve()
    sarif_path = Path(args.sarif).resolve()
    out_dir = Path(args.out_dir).resolve()
    tool = args.tool or sarif_path.stem

    rule_map = load_rule_cwe_map(Path(args.rule_cwe_map).resolve() if args.rule_cwe_map else None)
    regions = build_regions(src_root)
    points = build_expected_points(src_root, regions)
    findings = load_sarif(sarif_path, tool, src_root, rule_map)
    classify(regions, points, findings, cwe_aware=args.cwe_aware, window=args.line_window)

    out_dir.mkdir(parents=True, exist_ok=True)
    write_summary(out_dir, tool, points, findings)
    write_by_cwe(out_dir, tool, points, findings)
    write_points(out_dir, tool, points)
    write_regions(out_dir, tool, regions)
    write_findings(out_dir, tool, findings)

    if args.emit_defectdojo:
        include_statuses = [item.strip().upper() for item in args.dojo_include.split(",") if item.strip()]
        write_dojo(out_dir, tool, points, include_statuses)

    counts = count_statuses(points, findings)
    print(
        f"{tool}: TP={counts['TP']} FP={counts['FP']} TN={counts['TN']} FN={counts['FN']} "
        f"findings={len(findings)} out_dir={out_dir}"
    )


if __name__ == "__main__":
    main()
