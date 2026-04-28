import csv
import json
import re
CSV_FILE = "expectedresults-1.2.csv"
SONAR_JSON = "resultsJavaSonar.json"

SECURITY_TYPES = {"VULNERABILITY"}

ground_truth = {}

with open(CSV_FILE, newline='') as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith("#"):
            continue

        test_name = row[0].strip()
        is_vuln = row[2].strip().lower() == "true"

        ground_truth[test_name] = is_vuln

with open(SONAR_JSON) as f:
    data = json.load(f)

findings_by_test = {}

for issue in data["issues"]:

    component = issue.get("component", "")

    match = re.search(r"(BenchmarkTest\d+)", component)
    if not match:
        continue

    test_name = match.group(1)

    findings_by_test.setdefault(test_name, 0)
    findings_by_test[test_name] += 1

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

print("TP:", TP)
print("FP:", FP)
print("FN:", FN)
print("TN:", TN)

if TP + FP > 0:
    precision = TP / (TP + FP)
    print("Precision:", round(precision, 3))

if TP + FN > 0:
    recall = TP / (TP + FN)
    print("Recall:", round(recall, 3))

# TP: 210
# FP: 181
# FN: 1205
# TN: 1144
# Precision: 0.537
# Recall: 0.148