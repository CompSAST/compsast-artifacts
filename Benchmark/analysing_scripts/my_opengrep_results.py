import json
import csv
import re
from collections import defaultdict

SARIF_FILE = "resultsJavaOpengrep.sarif"
CSV_FILE = "expectedresults-1.2.csv"


def load_sarif(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def extract_test_name(uri):
    match = re.search(r'BenchmarkTest\d+', uri)
    return match.group(0) if match else None


def parse_sarif(sarif_data):
    detected_tests = set()
    details = defaultdict(list)

    for run in sarif_data.get("runs", []):
        for result in run.get("results", []):
            locations = result.get("locations", [])
            rule_id = result.get("ruleId")
            message = result.get("message", {}).get("text", "")

            for loc in locations:
                uri = loc["physicalLocation"]["artifactLocation"]["uri"]
                test_name = extract_test_name(uri)

                if test_name:
                    detected_tests.add(test_name)
                    details[test_name].append({
                        "rule": rule_id,
                        "file": uri,
                        "message": message[:120]
                    })

    return detected_tests, details


def load_benchmark(csv_path):
    benchmark = {}

    with open(csv_path, newline='', encoding="utf-8") as f:
        reader = csv.reader(f)

        for row in reader:
            if not row or row[0].startswith("#"):
                continue

            test_name, category, real_vuln, cwe = row

            benchmark[test_name] = {
                "category": category,
                "real_vuln": real_vuln.lower() == "true",
                "cwe": cwe
            }

    return benchmark


def evaluate(detected, benchmark):
    TP = FP = FN = TN = 0

    for test, data in benchmark.items():
        real = data["real_vuln"]
        found = test in detected

        if real and found:
            TP += 1
        elif not real and found:
            FP += 1
        elif real and not found:
            FN += 1
        else:
            TN += 1

    return TP, FP, FN, TN


def print_metrics(TP, FP, FN, TN):
    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0

    print("\n=== METRICS ===")
    print(f"TP: {TP}")
    print(f"FP: {FP}")
    print(f"FN: {FN}")
    print(f"TN: {TN}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")


def main():
    sarif = load_sarif(SARIF_FILE)
    detected, details = parse_sarif(sarif)

    benchmark = load_benchmark(CSV_FILE)

    TP, FP, FN, TN = evaluate(detected, benchmark)

    print_metrics(TP, FP, FN, TN)

    

if __name__ == "__main__":
    main()


# === RESULTS ===
# TP: 1307
# FP: 780
# FN: 108
# TN: 545
# Precision: 0.626
# Recall: 0.924