#!/usr/bin/env python3
"""IAMeter benchmark points from source comments + CWE from file name + sink."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import FrozenSet, List, Literal, Sequence, Tuple

Kind = Literal["tp", "fp", "fn"]


@dataclass(frozen=True)
class Point:
    relpath: str
    line: int
    kind: Kind
    cwe: int


STANDALONE_ANNOT = re.compile(
    r"//[^\n]*?\b(True positive|False positive|False negative)\b",
    re.I,
)


def _is_xxe_file(relpath: str) -> bool:
    return "xxe" in relpath.lower()


def infer_cwe_sink(relpath: str, code_line: str) -> int:
    if not _is_xxe_file(relpath):
        return 79
    low = code_line.lower()
    if any(
        x in low
        for x in (
            "simplexml_load_string",
            "documentbuilder",
            ".parse(",
            "parse(parm1",
            "xmlparser",
        )
    ):
        return 611
    if "libxml_disable_entity_loader" in low:
        return 611
    return 79


def _annot_kind(fragment: str) -> Kind | None:
    s = re.sub(r"\s+", "", fragment.lower())
    if "falsenegative" in s:
        return "fn"
    if "falsepositive" in s:
        return "fp"
    if "truepositive" in s:
        return "tp"
    return None


def parse_file(path: Path, benchmark_root: Path, bench: str) -> List[Point]:
    root = (benchmark_root / bench).resolve()
    relpath = str(path.resolve().relative_to(root)).replace("\\", "/")
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    out: List[Point] = []

    for i0, raw in enumerate(lines):
        lineno = i0 + 1

        if ";" in raw and "//" in raw:
            after = raw.split("//", 1)[1]
            k = _annot_kind(after)
            if k is not None:
                out.append(Point(relpath, lineno, k, infer_cwe_sink(relpath, raw)))
                continue

        m = STANDALONE_ANNOT.search(raw)
        if not m:
            continue
        k = _annot_kind(m.group(0))
        if k is None:
            continue
        j = i0 + 1
        while j < len(lines):
            nxt = lines[j].strip()
            if not nxt or nxt in ("{", "}"):
                j += 1
                continue
            if nxt.startswith("//") and not STANDALONE_ANNOT.search(lines[j]):
                j += 1
                continue
            if nxt.startswith("/*") or nxt.startswith("*"):
                j += 1
                continue
            line_no = j + 1
            out.append(
                Point(relpath, line_no, k, infer_cwe_sink(relpath, lines[j]))
            )
            break

    seen = set()
    uniq: List[Point] = []
    for p in out:
        t = (p.relpath, p.line, p.kind, p.cwe)
        if t in seen:
            continue
        seen.add(t)
        uniq.append(p)

    return sorted(uniq, key=lambda x: (x.relpath, x.line))


def _java_paths(benchmark_root: Path, bench: str) -> List[Path]:
    d = benchmark_root / bench / "src" / "main" / "java" / "iameter"
    return sorted(d.glob("*.java")) if d.is_dir() else []


def _go_paths(benchmark_root: Path, bench: str) -> List[Path]:
    d = benchmark_root / bench / "api"
    return sorted(d.glob("*.go")) if d.is_dir() else []


def _php_paths(benchmark_root: Path, bench: str) -> List[Path]:
    d = benchmark_root / bench
    return sorted(
        p for p in d.glob("*.php") if p.is_file() and p.name not in {"index.php"}
    )


def load_benchmark_points(benchmark_root: Path, bench: str) -> List[Point]:
    if bench == "IAMeter_Java":
        globs = _java_paths
    elif bench == "IAMeter_Go":
        globs = _go_paths
    elif bench == "IAMeter_PHP":
        globs = _php_paths
    else:
        raise ValueError(bench)
    pts: List[Point] = []
    for p in globs(benchmark_root, bench):
        pts.extend(parse_file(p, benchmark_root, bench))
    return sorted(pts, key=lambda x: (x.relpath, x.line))


def ground_truth_targets(cwe: int, points: Sequence[Point]) -> FrozenSet[Tuple[str, int]]:
    s: set[Tuple[str, int]] = set()
    for p in points:
        if p.cwe == cwe and p.kind in ("tp", "fn"):
            s.add((p.relpath, p.line))
    return frozenset(s)


def trap_fp_lines(cwe: int, points: Sequence[Point]) -> FrozenSet[Tuple[str, int]]:
    s: set[Tuple[str, int]] = set()
    for p in points:
        if p.cwe == cwe and p.kind == "fp":
            s.add((p.relpath, p.line))
    return frozenset(s)
