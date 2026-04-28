import csv
import json
import re
from collections import defaultdict

CSV_FILE = "expectedresults-1.2.csv"
PMD_FILE = "reportPMDJava.sarif"

PMD_RULE_TO_CWE = {
    "CloseResource": 404,
    "AvoidFileStream": 22,
    "AvoidRuntimeExec": 78,
    "JspEncoding": 79,
    "XSSRequestWrapper": 79,
    "InsecureCrypto": 327,
    "WeakCipher": 327,
    "WeakHash": 328,
    "UnvalidatedServletOutput": 501,
    "LdapInjection": 90,
    "XxeProcessing": 611,
    "InsecureRandom": 330,
    "NonThreadSafeSingleton": 362,
    "StackTraceExposure": 209,
    "AvoidUsingHardCodedIP": 798,
    "HardcodedCryptoKey": 321,
}

SECURITY_CWES = {22, 78, 79, 89, 90, 327, 328, 330, 501, 563, 611, 209, 321, 362, 404, 798}

ground_truth = {}
test_category = {}
test_cwe = {}

with open(CSV_FILE, newline='') as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        
        test_name = row[0].strip()
        category = row[1].strip() if len(row) > 1 else ""
        is_vuln = row[2].strip().lower() == "true" if len(row) > 2 else False
        cwe = int(row[3].strip()) if len(row) > 3 and row[3].strip() else None
        
        ground_truth[test_name] = is_vuln
        test_category[test_name] = category
        test_cwe[test_name] = cwe

print(f"Total ground truth tests: {len(ground_truth)}")
print(f"  - Vulnerable: {sum(ground_truth.values())}")
print(f"  - Non-vulnerable: {len(ground_truth) - sum(ground_truth.values())}")

with open(PMD_FILE) as f:
    sarif = json.load(f)

security_findings_by_test = defaultdict(list)
all_security_warnings = 0
all_pmd_warnings = 0
unmapped_rules = set()

for run in sarif.get("runs", []):
    results = run.get("results", [])
    
    for result in results:
        rule_id = result.get("ruleId", "")
        all_pmd_warnings += 1
        
        cwe = PMD_RULE_TO_CWE.get(rule_id)
        
        if cwe is None:
            unmapped_rules.add(rule_id)
            continue
        
        if cwe not in SECURITY_CWES:
            continue
        
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
        security_findings_by_test[test_name].append((rule_id, cwe))
        all_security_warnings += 1

print(f"\n=== PMD Analysis ===")
print(f"Total PMD warnings: {all_pmd_warnings}")
print(f"Security-relevant warnings: {all_security_warnings}")
print(f"Unique tests with security findings: {len(security_findings_by_test)}")

if unmapped_rules:
    print(f"\nUnmapped PMD rules (not considered security-relevant):")
    for rule in sorted(unmapped_rules)[:15]:
        print(f"  - {rule}")
    if len(unmapped_rules) > 15:
        print(f"  ... and {len(unmapped_rules) - 15} more")

if security_findings_by_test:
    rules_counter = defaultdict(int)
    for rules in security_findings_by_test.values():
        for rule, _ in rules:
            rules_counter[rule] += 1
    
    print(f"\nTop security-relevant PMD rules triggered:")
    for rule, count in sorted(rules_counter.items(), key=lambda x: -x[1])[:10]:
        cwe = PMD_RULE_TO_CWE.get(rule, '?')
        print(f"  {rule} (CWE-{cwe}): {count} occurrences")
    
    print(f"\nFirst 10 tests with security findings:")
    for i, test in enumerate(list(security_findings_by_test.keys())[:10]):
        rules_info = ', '.join([f"{r}(CWE-{c})" for r, c in security_findings_by_test[test][:3]])
        print(f"  {test}: {rules_info}")

TP = FP = FN = TN = 0

false_positives = []
false_negatives = []

for test_name, is_vuln in ground_truth.items():
    detected = test_name in security_findings_by_test
    
    if detected and is_vuln:
        TP += 1
    elif detected and not is_vuln:
        FP += 1
        false_positives.append(test_name)
    elif not detected and is_vuln:
        FN += 1
        false_negatives.append(test_name)
    else:
        TN += 1

print("\n" + "="*60)
print("PMD SECURITY-RELEVANT RESULTS")
print("="*60)
print(f"TP (True Positives):  {TP}")
print(f"FP (False Positives): {FP}")
print(f"FN (False Negatives): {FN}")
print(f"TN (True Negatives):  {TN}")
print("-"*60)

if TP + FP > 0:
    precision = TP / (TP + FP)
    print(f"Precision: {round(precision, 3)}")
else:
    precision = 0
    print("Precision: N/A")

if TP + FN > 0:
    recall = TP / (TP + FN)
    print(f"Recall: {round(recall, 3)}")
else:
    recall = 0
    print("Recall: N/A")

if precision + recall > 0:
    f1 = 2 * (precision * recall) / (precision + recall)
    print(f"F1-score: {round(f1, 3)}")
else:
    print("F1-score: N/A")

print("\n" + "="*60)
print("PERFORMANCE BY VULNERABILITY CATEGORY")
print("="*60)

categories_stats = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "total": 0})

for test_name, is_vuln in ground_truth.items():
    category = test_category.get(test_name, "unknown")
    detected = test_name in security_findings_by_test
    
    if detected and is_vuln:
        categories_stats[category]["TP"] += 1
    elif detected and not is_vuln:
        categories_stats[category]["FP"] += 1
    elif not detected and is_vuln:
        categories_stats[category]["FN"] += 1
    else:
        categories_stats[category]["TN"] += 1
    categories_stats[category]["total"] += 1

for category, stats in sorted(categories_stats.items()):
    if stats["total"] == 0:
        continue
    
    tp, fp, fn = stats["TP"], stats["FP"], stats["FN"]
    
    if tp + fp > 0:
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0
    else:
        prec = 0
    
    if tp + fn > 0:
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0
    else:
        rec = 0
    
    if prec + rec > 0:
        f1_cat = 2 * (prec * rec) / (prec + rec) if (prec + rec) > 0 else 0
    else:
        f1_cat = 0
    
    print(f"\n{category.upper()}:")
    print(f"  Detected: {tp+fp}/{stats['total']} ({round((tp+fp)/stats['total']*100, 1)}% of tests)")
    print(f"  TP={tp}, FP={fp}, FN={fn}")
    print(f"  Precision={round(prec, 3)}, Recall={round(rec, 3)}, F1={round(f1_cat, 3)}")

if false_positives:
    print(f"\n" + "="*60)
    print(f"FALSE POSITIVES (first 20 of {len(false_positives)})")
    print("="*60)
    for test in false_positives[:20]:
        expected_cwe = test_cwe.get(test, '?')
        found_rules = security_findings_by_test.get(test, [])
        rules_str = ', '.join([f"{r}(CWE-{c})" for r, c in found_rules[:3]])
        print(f"  {test}: expected CWE-{expected_cwe}, found {rules_str}")

if false_negatives:
    print(f"\n" + "="*60)
    print(f"FALSE NEGATIVES (first 20 of {len(false_negatives)})")
    print("="*60)
    for test in false_negatives[:20]:
        expected_cwe = test_cwe.get(test, '?')
        category = test_category.get(test, '?')
        print(f"  {test}: CWE-{expected_cwe}, category={category}")




# ============================================================
# PMD SECURITY-RELEVANT RESULTS
# ============================================================
# TP (True Positives):  462
# FP (False Positives): 407
# FN (False Negatives): 953
# TN (True Negatives):  918
# ------------------------------------------------------------
# Precision: 0.532
# Recall: 0.327
# F1-score: 0.405