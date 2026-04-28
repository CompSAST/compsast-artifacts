import json
import csv
import re
from collections import defaultdict

JOERN_REPORT_PATH = "resultsJoernJava.json"
GROUND_TRUTH_PATH = "expectedresults-1.2.csv"

def extract_test_name(text):
    """
    Ищет BenchmarkTestXXXXX в строке
    """
    if not text:
        return None
    match = re.search(r'BenchmarkTest\d+', text)
    return match.group(0) if match else None


def load_joern_results(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    detected_tests = set()

    for item in data:
        filename = item.get("filename", "")
        fullname = item.get("fullName", "")

        test_name = extract_test_name(filename) or extract_test_name(fullname)

        if test_name:
            detected_tests.add(test_name)

    return detected_tests


def load_ground_truth(path):
    gt = {}

    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue

            test_name = row[0].strip()
            is_vuln = row[2].strip().lower() == "true"

            gt[test_name] = is_vuln

    return gt


def calculate_metrics(detected, ground_truth):
    TP = FP = TN = FN = 0

    for test, is_vuln in ground_truth.items():
        predicted = test in detected

        if predicted and is_vuln:
            TP += 1
        elif predicted and not is_vuln:
            FP += 1
        elif not predicted and not is_vuln:
            TN += 1
        elif not predicted and is_vuln:
            FN += 1

    precision = TP / (TP + FP) if (TP + FP) else 0
    recall = TP / (TP + FN) if (TP + FN) else 0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0

    return {
        "TP": TP,
        "FP": FP,
        "TN": TN,
        "FN": FN,
        "precision": precision,
        "recall": recall,
        "f1": f1
    }

def main():
    detected = load_joern_results(JOERN_REPORT_PATH)
    ground_truth = load_ground_truth(GROUND_TRUTH_PATH)

    metrics = calculate_metrics(detected, ground_truth)

    print("Detected tests:", len(detected))
    print("Total tests:", len(ground_truth))
    print()

    print("TP:", metrics["TP"])
    print("FP:", metrics["FP"])
    print("TN:", metrics["TN"])
    print("FN:", metrics["FN"])
    print()

    print("Precision:", round(metrics["precision"], 4))
    print("Recall:", round(metrics["recall"], 4))
    print("F1:", round(metrics["f1"], 4))


if __name__ == "__main__":
    main()



# TP: 452
# FP: 778
# TN: 0
# FN: 0

# Precision: 0.3675
# Recall: 1.0
# F1: 0.5375