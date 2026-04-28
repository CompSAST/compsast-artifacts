#!/usr/bin/env python3
"""
Pull SonarQube issues via REST API (paginated ``api/issues/search``) and write SARIF 2.1.0.

``sonar-scanner`` does not emit SARIF; SonarQube exposes findings through the Web API after analysis.

Typical usage (after scanner finished on the server):

.. code-block:: bash

   export SONAR_TOKEN=...
   python3 compsast-artifacts/sonar_issues_to_sarif.py \\
     --host http://localhost:9000 \\
     --project-key iameter_go \\
     -o IAMeter_Go/sonarqube.sarif

Environment (optional): ``SONAR_HOST_URL``, ``SONAR_TOKEN``, ``SONAR_PROJECT_KEY`` as defaults.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def _level(sonar_severity: str) -> str:
    s = (sonar_severity or "").upper()
    if s in ("BLOCKER", "CRITICAL"):
        return "error"
    if s in ("MAJOR", "MINOR"):
        return "warning"
    return "note"


def _fetch_page(
    host: str,
    token: str,
    project_key: str,
    page: int,
    page_size: int,
) -> Dict[str, Any]:
    q = urllib.parse.urlencode(
        {
            "componentKeys": project_key,
            "p": str(page),
            "ps": str(page_size),
            "resolved": "false",
        }
    )
    url = f"{host.rstrip('/')}/api/issues/search?{q}"
    req = urllib.request.Request(url)
    auth = base64.b64encode(f"{token}:".encode("utf-8")).decode("ascii")
    req.add_header("Authorization", f"Basic {auth}")
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _issue_to_result(issue: Dict[str, Any], project_key: str) -> Optional[Dict[str, Any]]:
    comp = issue.get("component") or ""
    # "projectKey:relative/path"
    rel = comp
    if ":" in comp:
        prefix, rest = comp.split(":", 1)
        if prefix == project_key:
            rel = rest
    tr = issue.get("textRange") or {}
    start_line = int(tr.get("startLine") or issue.get("line") or 1)
    region: Dict[str, Any] = {"startLine": start_line}
    if "endLine" in tr:
        region["endLine"] = int(tr["endLine"])
    if "startOffset" in tr:
        region["startColumn"] = int(tr["startOffset"])
    if "endOffset" in tr:
        region["endColumn"] = int(tr["endOffset"])
    msg = (issue.get("message") or "").strip() or issue.get("rule", "")
    rid = issue.get("rule") or "sonarqube/unknown"
    return {
        "ruleId": rid,
        "level": _level(issue.get("severity") or ""),
        "message": {"text": msg},
        "properties": {
            "sonar.issueKey": issue.get("key", ""),
            "sonar.severity": issue.get("severity", ""),
            "sonar.type": issue.get("type", ""),
            "sonar.status": issue.get("status", ""),
        },
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": rel},
                    "region": region,
                }
            }
        ],
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="SonarQube issues → SARIF via Web API")
    ap.add_argument("--host", default=os.environ.get("SONAR_HOST_URL", "http://localhost:9000"))
    ap.add_argument(
        "--token",
        default=os.environ.get("SONAR_TOKEN", ""),
        help="User token (also SONAR_TOKEN)",
    )
    ap.add_argument(
        "--project-key",
        "-k",
        default=os.environ.get("SONAR_PROJECT_KEY", ""),
        help="sonar.projectKey (also SONAR_PROJECT_KEY)",
    )
    ap.add_argument("-o", "--output", type=argparse.FileType("w", encoding="utf-8"), required=True)
    ap.add_argument("--ps", type=int, default=500, help="Page size (max 500)")
    args = ap.parse_args()
    if not args.token.strip():
        print("Set --token or SONAR_TOKEN", file=sys.stderr)
        return 1
    if not args.project_key.strip():
        print("Set --project-key or SONAR_PROJECT_KEY", file=sys.stderr)
        return 1

    project_key = args.project_key.strip()
    results: List[Dict[str, Any]] = []
    page = 1
    total_loaded = 0
    while True:
        try:
            data = _fetch_page(args.host, args.token.strip(), project_key, page, min(args.ps, 500))
        except urllib.error.HTTPError as e:
            print(f"HTTP {e.code}: {e.reason}", file=sys.stderr)
            print(e.read().decode("utf-8", errors="replace")[:2000], file=sys.stderr)
            return 1
        issues = data.get("issues") or []
        for iss in issues:
            r = _issue_to_result(iss, project_key)
            if r:
                results.append(r)
        total_loaded += len(issues)
        page_size = int(data.get("paging", {}).get("pageSize") or len(issues) or 0)
        total = int(data.get("paging", {}).get("total") or total_loaded)
        if total_loaded >= total or not issues:
            break
        page += 1

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    doc = {
        "version": "2.1.0",
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SonarQube",
                        "informationUri": "https://www.sonarsource.com/",
                        "rules": [],
                    }
                },
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": now,
                    }
                ],
                "results": results,
            }
        ],
    }
    json.dump(doc, args.output, ensure_ascii=False, indent=2)
    args.output.write("\n")
    print(f"Wrote {len(results)} result(s) to {args.output.name}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
