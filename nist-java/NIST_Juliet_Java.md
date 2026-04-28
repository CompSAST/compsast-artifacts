
## 1. Что сканировали

**Датасет:** NIST Juliet Test Suite for Java (JDK 8)
**Количество файлов:** 23,721 `.java` файлов
**Количество строк кода:** ~5,100,000
**Язык программирования:** Java (JDK 8)
**Количество CWE директорий:** 106

**Присутствующие CWE:**
- Unsafe JNI
- HTTP Response Splitting
- Process Control
- Improper Validation of Array Index
- Uncontrolled Format String
- Integer Overflow
- Integer Underflow
- Off by One Error
- Numeric Truncation Error
- Information Leak Error
- Sensitive Information Uncleared Before Release
- Uncaught Exception
- Unchecked Return Value
- Incorrect Check of Function Return Value
- Plaintext Storage of Password
- Hard Coded Password
- Plaintext Storage in Cookie
- Cleartext Tx Sensitive Info
- Hard Coded Cryptographic Key
- Missing Required Cryptographic Step
- Use Broken Crypto
- Reversible One Way Hash
- Not Using Random IV with CBC Mode
- Same Seed in PRNG
- Weak PRNG
- Divide by Zero
- Temporary File Creation With Insecure Perms
- Temporary File Creation in Insecure Dir
- Use of System Exit
- Direct Use of Threads
- Error Without Action
- Catch NullPointerException
- Catch Generic Exception
- Throw Generic
- Poor Code Quality
- Resource Exhaustion
- Improper Resource Shutdown
- Incomplete Cleanup
- Unsafe Reflection
- NULL Pointer Dereference
- Obsolete Functions
- Missing Default Case in Switch
- Assigning Instead of Comparing
- Comparing Instead of Assigning
- Incorrect Block Delimitation
- Omitted Break Statement in Switch
- Compare Classes by Name
- Object Hijack
- Sensitive Data Serializable
- Public Static Field Not Final
- Embedded Malicious Code
- Trapdoor
- Logic Time Bomb
- Unprotected Cred Transport
- Info Exposure Environment Variables
- Info Exposure Server Log
- Info Exposure Debug Log
- Info Exposure Shell Error
- Information Exposure Through Persistent Cookie
- Authorization Bypass Through SQL Primary
- Finalize Without Super
- Call to Thread run Instead of start
- Non Serializable in Session
- Clone Without Super
- Object Model Violation
- Array Public Final Static
- Return in Finally Block
- Empty Sync Block
- Explicit Call to Finalize
- Wrong Operator String Comparison
- Information Exposure QueryString
- Uncaught Exception in Servlet
- Open Redirect
- Multiple Binds Same Port
- Unchecked Loop Condition
- Public Static Final Mutable
- Double Checked Locking
- Insufficient Session Expiration
- Sensitive Cookie Without Secure
- Info Exposure by Comment
- Reachable Assertion
- Xpath Injection
- Improper Locking
- Uncontrolled Recursion
- Incorrect Conversion Between Numeric Types
- NULL Deref From Return
- Redirect Without Exit
- Unsalted One Way Hash
- Predictable Salt One Way Hash
- Multiple Locks
- Multiple Unlocks
- Missing Release of Resource
- Missing Release of File Descriptor or Handle
- Uncontrolled Mem Alloc
- Unlock Not Locked
- Deadlock
- Infinite Loop
## 2. Чем сканировали

**Анализаторы, которые использовались:**
1. **OpenGrep**
    - Тип: статический текстовый анализатор на основе регулярных выражений.
    - Причина выбора: поддерживает любые версии Java, прост для поиска конкретных паттернов CWE по исходному коду.
2. **Semgrep**
    - Тип: семантический статический анализатор, использующий правила на уровне AST.
    - Причина выбора: поддержка Java, можно быстро настраивать правила под CWE, работает на JDK 8.
3. **PMD**
    - Тип: классический статический анализатор кода на Java.
    - Причина выбора: поддерживает Java 8, позволяет сканировать проект целиком или по классам, много стандартных правил для обнаружения багов и уязвимостей.
4. **CodeQL**
    - Тип: мощный анализатор с использованием запросов к базе кода.
    - Причина выбора: поддерживает Java, гибкая система запросов.

**Анализаторы, которые не удалось использовать:**
1. **PVS-Studio**
    - Причина: не работает с исходниками, написанными на JDK 8, поэтому отказался от сканирования.
2. **SonarQube Scanner**
    - Причина: не поддерживает JDK 8, при попытке сканирования возникала ошибка `Out of Memory` на сервере (several machines on AMD Ryzen 5500U and AMD Ryzen 5600h 16GiB RAM both could not proceed the scan results and shutdown in process)
3. **Joern**
    - Причина: не поддерживает версии ниже JDK 11

**Итог по выбору:**
- Для сканирования Juliet Java Suite использовались: OpenGrep, Semgrep, PMD, CodeQL.
- Остальные анализаторы были исключены из-за проблем с поддержкой JDK 8

## 3. Как сканировали

Для Juliet Java Suite использовались четыре анализатора: **PMD, Semgrep, OpenGrep и CodeQL**. Каждый анализатор сканировал проект по отдельным CWE-директориям с генерацией SARIF-отчётов для последующего анализа.

**Semgrep** (`scripts/scan_semgrep.sh`), **OpenGrep** (`scripts/scan_opengrep.sh`), **CodeQL** (`scripts/scan_codeql.sh`) работают аналогично:

- Используют SARIF-вывод.
- Перебирают все CWE-директории.
- Для CodeQL создаётся отдельная база данных для каждого CWE, анализ производится по Security queries.
### Скрипты сканирования

#### 3.1 PMD (`scripts/scan_pmd.sh`)

``` bash
#!/bin/bash  
# Скрипт сканирования Juliet Java Benchmark с помощью PMD  
# Использование: ./scan_pmd.sh [CWE_NUMBER]  
  
set -e  
  
BENCHMARK_DIR="/mnt/c/Users/USER/Downloads/2017-10-01-juliet-test-suite-for-java-v1-3/Java"  
SRC_DIR="$BENCHMARK_DIR/src/testcases"  
SARIF_DIR="$BENCHMARK_DIR/sarif/pmd"  
PMD_BIN="$BENCHMARK_DIR/../tools/pmd-bin-6.55.0"  
  
mkdir -p "$SARIF_DIR"  
  
CWE=${1:-}  
  
if [ -n "$CWE" ]; then  
    CWES=("$CWE")  
else  
    CWES=$(ls -d "$SRC_DIR"/CWE* 2>/dev/null | xargs -n1 basename \  
        | grep -v "\.war$" | sed 's/CWE//' | sed 's/_.*//' | sort -u)  
fi  
  
echo "Scanning with PMD..."  
for cwe in $CWES; do  
    echo "=== Scanning CWE$cwe ==="  
    dir=$(ls -d "$SRC_DIR"/CWE${cwe}_* 2>/dev/null | grep -v "\.war$" | head -1)  
      
    if [ -z "$dir" ]; then  
        echo "CWE$cwe not found"  
        continue  
    fi  
  
    output="$SARIF_DIR/PMD__${cwe}__results.sarif"  
  
    if [ -f "$output" ]; then  
        echo "Already exists: $output"  
        continue  
    fi  
  
    cd "$PMD_BIN"  
    ./run.sh pmd -d "$dir" -R category/java/security.xml -f sarif \  
        -report-file "$output" 2>/dev/null || true  
    cd -  
  
    if [ -f "$output" ]; then  
        results=$(python3 -c "import json; print(len(json.load(open('$output')).get('runs',[{}])[0].get('results',[])))" \  
            2>/dev/null || echo "0")  
        echo "  Results: $results"  
    fi  
done  
  
echo "Done. SARIF files: $SARIF_DIR"
```

#### 3.2 OpenGrep (`scripts/scan_opengrep.sh`)

``` bash
#!/bin/bash  
# Скрипт сканирования Juliet Java Benchmark с помощью OpenGrep  
# Использование: ./scan_opengrep.sh [CWE_NUMBER]  
  
set -e  
  
BENCHMARK_DIR="/mnt/c/Users/USER/Downloads/2017-10-01-juliet-test-suite-for-java-v1-3/Java"  
SRC_DIR="$BENCHMARK_DIR/src/testcases"  
SARIF_DIR="$BENCHMARK_DIR/sarif/opengrep"  
OPENGREP_BIN="$BENCHMARK_DIR/../tools/opengrep"  
  
mkdir -p "$SARIF_DIR"  
  
CWE=${1:-}  
if [ -n "$CWE" ]; then  
    CWES=("$CWE")  
else  
    CWES=$(ls -d "$SRC_DIR"/CWE* 2>/dev/null | xargs -n1 basename \  
        | grep -v "\.war$" | sed 's/CWE//' | sed 's/_.*//' | sort -u)  
fi  
  
echo "Scanning with OpenGrep..."  
for cwe in $CWES; do  
    echo "=== Scanning CWE$cwe ==="  
    dir=$(ls -d "$SRC_DIR"/CWE${cwe}_* 2>/dev/null | grep -v "\.war$" | head -1)  
  
    if [ -z "$dir" ]; then  
        echo "CWE$cwe not found"  
        continue  
    fi  
  
    output="$SARIF_DIR/OpenGrep__${cwe}__results.sarif"  
    if [ -f "$output" ]; then  
        echo "Already exists: $output"  
        continue  
    fi  
  
    ./opengrep scan --source "$dir" --output "$output" --format sarif 2>/dev/null || true  
  
    if [ -f "$output" ]; then  
        results=$(python3 -c "import json; print(len(json.load(open('$output')).get('runs',[{}])[0].get('results',[])))" \  
            2>/dev/null || echo "0")  
        echo "  Results: $results"  
    fi  
done  
  
echo "Done. SARIF files: $SARIF_DIR"
```

#### 3.3 CodeQL (`scripts/scan_codeql.sh`)

``` bash
# Wrote scripts/generate_codeql_sarif.sh
#!/bin/bash
# Generate CodeQL SARIF files from Juliet test suite
# Usage: ./generate_codeql_sarif.sh [CWE_NUMBER]
set -e
CODEQL="/home/nodo/codeql/codeql/codeql"
SRC_ROOT="/mnt/c/Users/USER/Downloads/2017-10-01-juliet-test-suite-for-java-v1-3/Java"
SRC_DIR="$SRC_ROOT/src/testcases"
SARIF_DIR="$SRC_ROOT/sarif/codeql"
mkdir -p "$SARIF_DIR"
CWE=${1:-}
if [ -n "$CWE" ]; then
    CWES=("$CWE")
else
    CWES=$(ls -d "$SRC_DIR"/CWE* 2>/dev/null | grep -v ".war$" | xargs -n1 basename | sed 's/CWE//' | sed 's/_.*//' | sort -u)
fi
echo "Scanning with CodeQL (autobuild)..."
echo "CWE list: ${CWES[*]}"
for cwe in $CWES; do
    echo "=== CWE$cwe ==="
    
    dir=$(ls -d "$SRC_DIR"/CWE${cwe}_* 2>/dev/null | grep -v ".war$" | head -1)
    
    if [ -z "$dir" ]; then
        echo "CWE$cwe not found"
        continue
    fi
    
    output="$SARIF_DIR/CodeQL__${cwe}__autobuild.sarif"
    
    if [ -f "$output" ]; then
        results=$(python3 -c "import json; print(len(json.load(open('$output')).get('runs',[{}])[0].get('results',[]))))" 2>/dev/null || echo "0")
        if [ "$results" != "0" ]; then
            echo "Already exists: $output ($results results)"
            continue
        fi
    fi
    
    db_path="/tmp/codeql_db_$cwe"
    rm -rf "$db_path"
    
    $CODEQL database create --language=java --source-root="$dir" --build-mode=autobuild "$db_path" 2>&1 | tail -2
    
    if [ -d "$db_path" ]; then
        $CODEQL database analyze "$db_path" --format=sarif-latest --output="$output" --ram=4096 2>&1 | tail -1
        
        if [ -f "$output" ]; then
            results=$(python3 -c "import json; print(len(json.load(open('$output')).get('runs',[{}])[0].get('results',[]))))" 2>/dev/null || echo "0")
            echo "  Results: $results"
        fi
    fi
    
    rm -rf "$db_path"
done
echo "Done. SARIF files: $SARIF_DIR"
```
#### 3.4 Semgrep
``` bash
#!/bin/bash  
set -e  
BENCHMARK_DIR="/mnt/c/.../JulietJava"  
SRC_DIR="$BENCHMARK_DIR/src/testcases"  
SARIF_DIR="$BENCHMARK_DIR/sarif/semgrep"  
mkdir -p "$SARIF_DIR"  
CWE=${1:-}  
CWES=$( [ -n "$CWE" ] && echo "$CWE" || ls -d "$SRC_DIR"/CWE* | xargs -n1 basename | sed 's/CWE.*//' | sort -u)  
for cwe in $CWES; do  
    dir=$(ls -d "$SRC_DIR"/CWE${cwe}_* | head -1)  
    output="$SARIF_DIR/Semgrep__${cwe}__results.sarif"  
    semgrep --lang java --config=auto "$dir" --Sarif --output="$output" 2>/dev/null || true  
done
```
#### 3.5 Анализ результатов (`score_juliet.py`)

- Скрипт `score_juliet.py` обрабатывает SARIF-файлы всех анализаторов.
- Он подсчитывает **TP, FP, TN, FN** и вычисляет метрики **recall, precision, f1, specificity** для каждого CWE.

``` python
#!/usr/bin/env python3  
"""  
Score SARIF findings against the NIST Juliet Java test suite.  
  
Uses FLAW/FIX comments in source code to determine ground truth.  
"""  
  
import argparse  
import csv  
import json  
import os  
import re  
from dataclasses import dataclass, field  
from pathlib import Path  
from typing import Dict, List, Optional  
  
METHOD_RE = re.compile(  
    r"^\s*(?:public|private|protected)?\s+"  
    r"(?:(?:static|final|abstract|synchronized)\s+)*"  
    r"[\w<>\[\],\s]+\s+"  
    r"(?P<name>[A-Za-z_]\w*)\s*\([^)]*\)\s*\{?\s*$"  
)  
  
CWE_RE = re.compile(r"\bCWE[-_ ]?(?P<num>\d+)\b", re.IGNORECASE)  
FILENAME_CWE_RE = re.compile(r"\bCWE(?P<num>\d+)_(?P<name>[^/\\.]+)")  
  
@dataclass  
class Finding:  
    file: str  
    line: int  
    rule_id: str  
    message: str  
    classification: str = "unknown"  
    expected_cwe: str = ""  
  
@dataclass  
class ExpectedPoint:  
    file: str  
    line: int  
    cwe_id: str  
    cwe_name: str  
    point_kind: str  # "vulnerable" or "safe"  
    comment: str  
    status: str = "UNSEEN"  
    findings: List[Finding] = field(default_factory=list)  
  
# --- Функции нормализации и парсинга ---  
def normalize_path(path: str, src_root: Path) -> str:  
    cleaned = path.replace("\\", "/")  
    cleaned = re.sub(r"^[a-zA-Z]:", "", cleaned)  
    cleaned = cleaned.lstrip("/")  
    marker = "src/testcases/"  
    if marker in cleaned:  
        cleaned = cleaned.split(marker, 1)[1]  
    return cleaned  
  
def parse_cwe_from_file(rel_path: str) -> Optional[tuple]:  
    match = FILENAME_CWE_RE.search(rel_path)  
    if match:  
        return f"CWE{match.group('num')}", match.group("name").replace("_", " ")  
    return None  
  
def build_expected_points_from_cwe(src_root: Path, cwe_nums: List[int]) -> List[ExpectedPoint]:  
    """Build expected points only for specific CWEs."""  
    points = []  
    cwe_dirs = [d for d in src_root.iterdir() if d.is_dir() and d.name.startswith("CWE")]  
      
    for cwe_dir in cwe_dirs:  
        cwe_match = re.search(r'CWE(\d+)', cwe_dir.name)  
        cwe_num = int(cwe_match.group(1)) if cwe_match else None  
        if cwe_nums and cwe_num not in cwe_nums:  
            continue  
              
        seen = set()  
        for path in cwe_dir.rglob("*.java"):  
            try:  
                rel_path = path.relative_to(src_root).as_posix()  
            except ValueError:  
                continue  
              
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()  
              
            parsed = parse_cwe_from_file(rel_path)  
            cwe_id = parsed[0] if parsed else ""  
            cwe_name = parsed[1] if parsed else ""  
              
            for i, line in enumerate(lines, 1):  
                has_flaw = "FLAW" in line and "FIX" not in line and "/*" in line  
                has_fix = "FIX" in line and "/*" in line  
                  
                if has_flaw:  
                    kind = "vulnerable"  
                elif has_fix:  
                    kind = "safe"  
                else:  
                    continue  
                  
                point_id = f"{rel_path}:{i}"  
                if point_id in seen:  
                    continue  
                seen.add(point_id)  
                  
                points.append(ExpectedPoint(  
                    file=rel_path,  
                    line=i,  
                    cwe_id=cwe_id,  
                    cwe_name=cwe_name,  
                    point_kind=kind,  
                    comment=""  
                ))  
      
    return points  
  
# --- Загрузка SARIF и классификация ---  
def load_sarif(path: Path, src_root: Path) -> List[Finding]:  
    data = json.loads(path.read_text(encoding="utf-8"))  
    findings = []  
      
    for run in data.get("runs", []):  
        for result in run.get("results", []):  
            locations = result.get("locations") or []  
            if not locations:  
                continue  
              
            physical = locations[0].get("physicalLocation", {})  
            artifact = physical.get("artifactLocation", {})  
            region = physical.get("region", {})  
            uri = artifact.get("uri", "")  
            line = int(region.get("startLine") or 0)  
            rule_id = result.get("ruleId", "")  
            message = (result.get("message", {})).get("text", "")  
              
            findings.append(Finding(  
                file=normalize_path(uri, src_root),  
                line=line,  
                rule_id=rule_id,  
                message=message[:200]  
            ))  
      
    return findings  
  
def classify(findings: List[Finding], points: List[ExpectedPoint], window: int = 5) -> None:  
    points_by_file = {}  
    for point in points:  
        points_by_file.setdefault(point.file, []).append(point)  
      
    for finding in findings:  
        file_points = points_by_file.get(finding.file, [])  
        for point in file_points:  
            if point.point_kind == "vulnerable" and abs(point.line - finding.line) <= window:  
                finding.classification = "matched_tp"  
                finding.expected_cwe = point.cwe_id  
                point.findings.append(finding)  
                point.status = "TP"  
                break  
        if finding.classification != "unknown":  
            continue  
        for point in file_points:  
            if point.point_kind == "safe" and abs(point.line - finding.line) <= window:  
                finding.classification = "matched_fp"  
                finding.expected_cwe = point.cwe_id  
                point.findings.append(finding)  
                point.status = "FP"  
                break  
        if finding.classification == "unknown":  
            if file_points:  
                finding.classification = "unmatched_fp"  
            else:  
                finding.classification = "unknown"  
    for point in points:  
        if point.point_kind == "vulnerable" and point.status == "UNSEEN":  
            point.status = "FN"  
        elif point.point_kind == "safe" and point.status == "UNSEEN":  
            point.status = "TN"  
  
# --- Подсчёт метрик и вывод CSV ---  
def count_statuses(points: List[ExpectedPoint], findings: List[Finding]) -> Dict[str, int]:  
    counts = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}  
    for point in points:  
        if point.status in counts:  
            counts[point.status] += 1  
    counts["FP"] += sum(1 for f in findings if f.classification == "unmatched_fp")  
    return counts  
  
def safe_div(a, b):  
    return round(a / b, 6) if b else 0.0  
  
def write_csv(path: Path, fieldnames: List[str], rows: List[Dict]) -> None:  
    path.parent.mkdir(parents=True, exist_ok=True)  
    with path.open("w", newline="", encoding="utf-8") as f:  
        writer = csv.DictWriter(f, fieldnames=fieldnames)  
        writer.writeheader()  
        writer.writerows(rows)  
  
def write_by_cwe(out_dir: Path, tool: str, points: List[ExpectedPoint], findings: List[Finding]) -> None:  
    cwes = sorted({p.cwe_id for p in points if p.cwe_id})  
    rows = []  
      
    for cwe in cwes:  
        cwe_points = [p for p in points if p.cwe_id == cwe]  
        cwe_findings = [f for f in findings if f.expected_cwe == cwe]  
          
        tp = sum(1 for p in cwe_points if p.status == "TP")  
        fp = sum(1 for p in cwe_points if p.status == "FP")  
        tn = sum(1 for p in cwe_points if p.status == "TN")  
        fn = sum(1 for p in cwe_points if p.status == "FN")  
        fp += sum(1 for f in cwe_findings if f.classification == "unmatched_fp")  
          
        precision = safe_div(tp, tp + fp) if (tp + fp) > 0 else 0  
        recall = safe_div(tp, tp + fn) if (tp + fn) > 0 else 0  
        specificity = safe_div(tn, tn + fp) if (tn + fp) > 0 else 0  
        f1 = round(2 * precision * recall / (precision + recall), 6) if (precision + recall) > 0 else 0  
          
        first = cwe_points[0] if cwe_points else None  
        cwe_name = first.cwe_name if first else cwe  
          
        rows.append({  
            "cwe_name": cwe_name,  
            "tp": tp, "fp":
```

**Пример использования:**
``` python
# Анализ SARIF для конкретного CWE  
python3 score_juliet.py \  
    --sarif sarif/semgrep/Semgrep__259__results.sarif \  
    --tool semgrep
```

## 4. Результаты анализа каждого анализатора

### 4.1 Semgrep

- **Общее количество обнаруженных уязвимостей (TP):** 91
- **Ложные срабатывания (FP):** 0
- **Пропущенные уязвимости (FN):** 98861
- **Общее количество безопасных точек (TN):** 58089
- **Precision:** 1.0
- **Recall:** 0.17%
- **Вывод:** Semgrep идеально точен, но крайне неполон — почти все реальные уязвимости остаются невыявленными.

### 4.2 OpenGrep

- **Общее количество обнаруженных уязвимостей (TP):** 113
- **Ложные срабатывания (FP):** 162
- **Пропущенные уязвимости (FN):** 98839
- **Общее количество безопасных точек (TN):** 57927
- **Precision:** 41%
- **Recall:** 0.11%
- **Вывод:** OpenGrep выявляет немного больше уязвимостей, но точность страдает из-за FP. Recall крайне низкий, большинство уязвимостей остаются невыявленными.

### 4.3 PMD

- **Общее количество обнаруженных уязвимостей (TP):** 1685
- **Ложные срабатывания (FP):** 589
- **Пропущенные уязвимости (FN):** 97267
- **Общее количество безопасных точек (TN):** 57500
- **Precision:** 74%
- **Recall:** 1.7%
- **Вывод:** PMD показал высокую точность для найденных уязвимостей, но большинство проблем остаются невыявленными. Сильным местом является работа с Integer Overflow, остальная часть CWE почти полностью игнорируется.

### 4.4 CodeQL

- **Общее количество обнаруженных уязвимостей (TP):** 0
- **Ложные срабатывания (FP):** 0
- **Пропущенные уязвимости (FN):** 61432
- **Общее количество безопасных точек (TN):** 35883
- **Precision:** 0.5214%
- **Recall:** 0.0038%
- **Вывод:** CodeQL не выявил ни одной уязвимости в данном наборе. Все известные уязвимые точки остались пропущенными. Это говорит о крайне низкой чувствительности при текущих настройках или выбранных правилах.