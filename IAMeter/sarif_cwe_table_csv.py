#!/usr/bin/env python3
"""Regenerate IAMeter_* CSV tables: benchmark annots vs SARIF + full metrics."""

from __future__ import annotations

import csv
import io
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

from iameter_ground_truth import ground_truth_targets, load_benchmark_points
from iameter_metrics import Row, metrics_for_cwe, unmatched_in_benchmark_annots
from iameter_sarif import load_findings

ROOT = Path(__file__).resolve().parents[2]
HT = ROOT / "help-tools" / "IAMeter"
CWE_ORDER = (611, 79)
CWE_NAMES = {
    611: "Improper Restriction of XML External Entity Reference (XXE)",
    79: "Improper Neutralization of Input During Web Page Generation (XSS)",
}


def _fmt(x: float) -> str:
    s = f"{x:.6f}"
    return s.rstrip("0").rstrip(".") or "0"


def pooled_tool_row(
    rows: Sequence[Row], tgt_lens: Sequence[int], trap_lens: Sequence[int]
) -> Row:
    if len(rows) != len(tgt_lens) or len(rows) != len(trap_lens):
        raise ValueError("alignment")
    tp_m = sum(r.tp for r in rows)
    fp_m = sum(r.fp for r in rows)
    fn_m = sum(r.fn for r in rows)
    tn_m = sum(r.tn for r in rows)

    def div(a: float, b: float) -> float:
        return float(a / b) if b else 0.0

    precision_m = div(tp_m, tp_m + fp_m)
    wrec = [(r.recall * t, t) for r, t in zip(rows, tgt_lens) if t > 0]
    recall_m = div(sum(w for w, _ in wrec), sum(t for _, t in wrec)) if wrec else 0.0

    tw = sum(trap_lens)
    if tw > 0:
        specificity_m = sum(r.specificity * t for r, t in zip(rows, trap_lens)) / tw
    else:
        specificity_m = 1.0 if fp_m == 0 else 0.0
    denom = precision_m + recall_m
    f1_m = div(2 * precision_m * recall_m, denom) if denom else 0.0
    return Row(
        tp_m,
        fp_m,
        tn_m,
        fn_m,
        precision_m,
        recall_m,
        specificity_m,
        f1_m,
    )


def render_lang_csv(
    bench: str, tools: Sequence[Tuple[str, str]]
) -> Tuple[str, Dict[str, Sequence[Tuple[Row, int, int]]]]:
    pts = load_benchmark_points(ROOT, bench)
    csv_rows: List[List[str]] = [
        [
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
        ]
    ]
    pooled: Dict[str, List[Tuple[Row, int, int]]] = {}

    for label, relpath in tools:
        p = ROOT / relpath
        if not p.is_file():
            continue
        findings = load_findings(p, bench)
        csv_rows.append([f"--- {label} ---", "", "", "", "", "", "", "", "", ""])
        sec_rows: List[Row] = []
        tg_lens: List[int] = []
        trap_lens: List[int] = []
        for cwe in CWE_ORDER:
            r, tg_n, trap_n = metrics_for_cwe(pts, findings, cwe)
            tg_lens.append(tg_n)
            trap_lens.append(trap_n)
            sec_rows.append(r)
            csv_rows.append(
                [
                    f"CWE{cwe}",
                    CWE_NAMES[cwe],
                    str(r.tp),
                    str(r.fp),
                    str(r.tn),
                    str(r.fn),
                    _fmt(r.precision),
                    _fmt(r.recall),
                    _fmt(r.specificity),
                    _fmt(r.f1),
                ]
            )

        pooled[label] = list(zip(sec_rows, tg_lens, trap_lens))

    buf = io.StringIO()
    w = csv.writer(buf)
    for row in csv_rows:
        w.writerow(row)

    return buf.getvalue(), pooled


def unmatched_for(bench: str, relpath: str) -> int:
    pts = load_benchmark_points(ROOT, bench)
    findings = load_findings(ROOT / relpath, bench)
    return unmatched_in_benchmark_annots(pts, findings)


def main() -> None:
    runs: Sequence[
        Tuple[str, str, Tuple[Tuple[str, str], ...], Tuple[str, str]]
    ] = [
        (
            "java/IAMeter_Java.csv",
            "IAMeter_Java",
            (
                ("semgrep", "help-tools/IAMeter/java/semgrep.sarif"),
                ("opengrep", "help-tools/IAMeter/java/opengrep.sarif"),
                ("codeql", "help-tools/IAMeter/java/codeql-results.sarif"),
                ("sonar", "help-tools/IAMeter/java/sonarqube.sarif"),
                ("pmd", "help-tools/IAMeter/java/pmd-report.sarif"),
                ("pvs", "help-tools/IAMeter/java/pvs-iameter.sarif"),
                ("joern", "help-tools/IAMeter/java/joern-scan.sarif"),
            ),
            ("11", "9"),
        ),
        (
            "go/IAMeter_Go.csv",
            "IAMeter_Go",
            (
                ("semgrep", "help-tools/IAMeter/go/semgrep.sarif"),
                ("opengrep", "help-tools/IAMeter/go/opengrep.sarif"),
                ("codeql", "help-tools/IAMeter/go/codeql-results.sarif"),
                ("joern", "help-tools/IAMeter/go/joern-scan.sarif"),
            ),
            ("11", "12"),
        ),
        (
            "php/IAMeter_PHP.csv",
            "IAMeter_PHP",
            (
                ("semgrep", "help-tools/IAMeter/php/semgrep.sarif"),
                ("opengrep", "help-tools/IAMeter/php/opengrep.sarif"),
                ("sonar", "help-tools/IAMeter/php/sonarqube.sarif"),
                ("joern", "help-tools/IAMeter/php/joern-scan.sarif"),
            ),
            ("14", "15"),
        ),
    ]

    vpc = {r[1]: r[3][0] for r in runs}
    spc = {r[1]: r[3][1] for r in runs}
    bm_key = {
        "java/IAMeter_Java.csv": "IAMeter_Java",
        "go/IAMeter_Go.csv": "IAMeter_Go",
        "php/IAMeter_PHP.csv": "IAMeter_PHP",
    }

    total_rows: List[List[str]] = [
        [
            "benchmark",
            "tool",
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
            "unmatched_in_benchmark_files",
        ]
    ]

    for rel_csv, bench, tools, _meta in runs:
        text, pooled = render_lang_csv(bench, tools)
        (HT / rel_csv).parent.mkdir(parents=True, exist_ok=True)
        (HT / rel_csv).write_text(text, encoding="utf-8")

        for label, z in pooled.items():
            rs = [p[0] for p in z]
            ts = [p[1] for p in z]
            trs = [p[2] for p in z]
            pr = pooled_tool_row(rs, ts, trs)
            relpath = dict(tools)[label]
            u = unmatched_for(bench, relpath)
            total_rows.append(
                [
                    bm_key.get(rel_csv, bench),
                    label,
                    str(pr.tp),
                    str(pr.fp),
                    str(pr.tn),
                    str(pr.fn),
                    _fmt(pr.precision),
                    _fmt(pr.recall),
                    _fmt(pr.specificity),
                    _fmt(pr.f1),
                    vpc[bench],
                    spc[bench],
                    str(u),
                ]
            )

    buf = io.StringIO()
    w = csv.writer(buf)
    for row in total_rows:
        w.writerow(row)
    (HT / "total.csv").write_text(buf.getvalue(), encoding="utf-8")
    print(f"Written {runs[0][0]}, {runs[1][0]}, {runs[2][0]}, total.csv")


if __name__ == "__main__":
    main()

