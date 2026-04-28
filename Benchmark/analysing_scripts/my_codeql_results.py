import csv
import json
import re

CSV_FILE = "expectedresults-1.2.csv"
SARIF_FILE = "resultsCodeQLJava.json"

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
        
        rule_id = result.get("ruleId", "")
        
        locations = result.get("locations", [])
        if not locations:
            continue
        
        physical_location = locations[0].get("physicalLocation", {})
        artifact_location = physical_location.get("artifactLocation", {})
        uri = artifact_location.get("uri", "")
        
        match = re.search(r"(BenchmarkTest\d+)", uri)
        if not match:
            continue
        
        test_name = match.group(1)
        
        findings_by_test[test_name] = findings_by_test.get(test_name, 0) + 1

print("=== DEBUG ===")
print(f"Total unique tests with findings: {len(findings_by_test)}")
if findings_by_test:
    print(f"First 10: {list(findings_by_test.keys())[:10]}")
else:
    print("WARNING: No findings found in SARIF file!")
    print("Check that:")
    print("  1. The SARIF file path is correct")
    print("  2. CodeQL actually found issues")
    print("  3. The test names in SARIF match 'BenchmarkTestXXXXX' pattern")

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
print(f"TP: {TP}")
print(f"FP: {FP}")
print(f"FN: {FN}")
print(f"TN: {TN}")

if TP + FP > 0:
    precision = TP / (TP + FP)
    print(f"Precision: {round(precision, 3)}")
else:
    precision = 0
    print("Precision: N/A (TP+FP=0)")

if TP + FN > 0:
    recall = TP / (TP + FN)
    print(f"Recall: {round(recall, 3)}")
else:
    recall = 0
    print("Recall: N/A (TP+FN=0)")

if precision + recall > 0:
    f1 = 2 * (precision * recall) / (precision + recall)
    print(f"F1: {round(f1, 3)}")
else:
    print("F1: N/A")


# === RESULTS ===
# TP: 1373
# FP: 904
# FN: 42
# TN: 421
# Precision: 0.603
# Recall: 0.97
# F1: 0.744