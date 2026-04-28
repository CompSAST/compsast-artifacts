"""Point-/finding-level metrics vs IAMeter annotated ground truth."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Sequence, Set, Tuple

from iameter_ground_truth import (
    Point,
    ground_truth_targets,
    trap_fp_lines,
)


@dataclass
class Row:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    specificity: float
    f1: float


def _paths_match(a: str, b: str) -> bool:
    a, b = a.replace("\\", "/"), b.replace("\\", "/")
    if a == b:
        return True
    return a.endswith(b) or b.endswith(a)


LINE_SLACK = 2  # SARIF и разметка могут отличаться на 1–2 строки (один шаг IR/парсера)


def _on_location(
    f_rel: str, f_line: int, loc_set: Set[Tuple[str, int]], slack: int = LINE_SLACK
) -> bool:
    for t_rel, t_line in loc_set:
        if abs(f_line - t_line) > slack:
            continue
        if _paths_match(t_rel, f_rel):
            return True
    return False


def _finding_on_targets(
    findings: Sequence[Dict[str, Any]], cwe: int, targets: Set[Tuple[str, int]]
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in findings:
        if cwe not in f["cwes"]:
            continue
        if _on_location(f["relpath"], f["line"], targets):
            out.append(f)
    return out


def _finding_off_targets(
    findings: Sequence[Dict[str, Any]], cwe: int, targets: Set[Tuple[str, int]]
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in findings:
        if cwe not in f["cwes"]:
            continue
        if _on_location(f["relpath"], f["line"], targets):
            continue
        out.append(f)
    return out


def metrics_for_cwe(
    points: Sequence[Point], findings: Sequence[Dict[str, Any]], cwe: int
) -> Tuple[Row, int, int]:
    targets = ground_truth_targets(cwe, points)
    traps = trap_fp_lines(cwe, points)

    on_t = _finding_on_targets(findings, cwe, targets)
    off_t = _finding_off_targets(findings, cwe, targets)

    found_locs: Set[Tuple[str, int]] = set()
    for f in on_t:
        for tr, tl in targets:
            if abs(f["line"] - tl) > LINE_SLACK:
                continue
            if _paths_match(tr, f["relpath"]):
                found_locs.add((tr, tl))
                break

    tp_n = len(on_t)
    fn_n = len(targets) - len(found_locs)
    fp_n = len(off_t)

    traps_alerted: Set[Tuple[str, int]] = set()
    for f in off_t:
        if not _on_location(f["relpath"], f["line"], traps):
            continue
        for trp, tl in traps:
            if abs(f["line"] - tl) > LINE_SLACK:
                continue
            if _paths_match(trp, f["relpath"]):
                traps_alerted.add((trp, tl))
                break

    fp_trap = len(traps_alerted)
    tn_n = len(traps) - fp_trap

    def div(a: float, b: float) -> float:
        return float(a / b) if b else 0.0

    precision = div(tp_n, tp_n + fp_n)
    recall = div(len(found_locs), len(targets))
    # Negatives здесь только ложноположительные «ловушки» бенча: TN / (TN + FP_на_ловушках)
    specificity = div(tn_n, tn_n + fp_trap) if traps else (1.0 if fp_n == 0 else 0.0)

    denom = precision + recall
    f1 = div(2 * precision * recall, denom) if denom else 0.0

    row = Row(
        tp=tp_n,
        fp=fp_n,
        tn=tn_n,
        fn=fn_n,
        precision=precision,
        recall=recall,
        specificity=specificity,
        f1=f1,
    )
    return row, len(targets), len(traps)


def unmatched_in_benchmark_annots(
    points: Sequence[Point], findings: Sequence[Dict[str, Any]]
) -> int:
    known_files = {p.relpath for p in points}
    known_base = {Path(p).name for p in known_files}
    n = 0
    for f in findings:
        rel = f["relpath"].replace("\\", "/")
        base = Path(rel).name
        if any(_paths_match(rel, kf) for kf in known_files):
            continue
        if base in known_base:
            continue
        n += 1
    return n
