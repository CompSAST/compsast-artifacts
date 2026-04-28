import csv
import json
import re

CSV_FILE = "expectedresults-1.2.csv"
PVS_FILE = "reportPVS-StudioJava.json"

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

print(f"Total ground truth tests: {len(ground_truth)}")

with open(PVS_FILE) as f:
    pvs_data = json.load(f)

findings_by_test = {}

warnings = pvs_data.get("warnings", [])

for warning in warnings:
    code = warning.get("code", "")
    if RULE_FILTER:
        if code not in RULE_FILTER:
            continue
    
    positions = warning.get("positions", [])
    if not positions:
        continue
    
    file_path = positions[0].get("file", "")
    
    match = re.search(r"(BenchmarkTest\d+)", file_path)
    if not match:
        continue
    
    test_name = match.group(1)
    
    findings_by_test[test_name] = findings_by_test.get(test_name, 0) + 1

print(f"\n=== DEBUG ===")
print(f"Total warnings in PVS report: {len(warnings)}")
print(f"Unique tests with findings: {len(findings_by_test)}")

if findings_by_test:
    print(f"First 10: {list(findings_by_test.keys())[:10]}")
else:
    print("\nWARNING: No BenchmarkTest findings found in PVS-Studio report!")
    print("Check that:")
    print("  1. The file path is correct")
    print("  2. The report contains warnings with file paths")
    print("  3. File paths contain 'BenchmarkTest' pattern")

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