import csv
import json
import re

CSV_FILE = "expectedresults-1.2.csv"
SARIF_FILE = "resultsJavaSemgrep.sarif"

RULE_FILTER = None

ground_truth = {}

with open(CSV_FILE, newline='') as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith("#"):
            continue

        test_name = row[0].strip()
        is_vuln = row[2].strip().lower() == "true"

        ground_truth[test_name] = is_vuln

with open(SARIF_FILE) as f:
    sarif = json.load(f)

findings_by_test = {}

for run in sarif.get("runs", []):
    for result in run.get("results", []):

        rule_id = result.get("ruleId", "").lower()

        if RULE_FILTER:
            if not any(x in rule_id for x in RULE_FILTER):
                continue

        locations = result.get("locations", [])
        if not locations:
            continue

        uri = locations[0]["physicalLocation"]["artifactLocation"]["uri"]

        match = re.search(r"(BenchmarkTest\d+)", uri)
        if not match:
            continue

        test_name = match.group(1)

        findings_by_test.setdefault(test_name, 0)
        findings_by_test[test_name] += 1

print("Total matched tests:", len(findings_by_test))
print("Example:", list(findings_by_test.keys())[:10])

TP = FP = FN = TN = 0

for test_name, is_vuln in ground_truth.items():
    detected = test_name in findings_by_test

    if detected and is_vuln:
        TP += 1
    elif detected and not is_vuln:
        FP += 1
    elif not detected and is_vuln:
        FN += 1
    else:
        TN += 1

print("\n=== RESULTS ===")
print("TP:", TP)
print("FP:", FP)
print("FN:", FN)
print("TN:", TN)

if TP + FP > 0:
    print("Precision:", round(TP / (TP + FP), 3))

if TP + FN > 0:
    print("Recall:", round(TP / (TP + FN), 3))




# === RESULTS ===
# TP: 1307
# FP: 780
# FN: 108
# TN: 545
# Precision: 0.626
# Recall: 0.924