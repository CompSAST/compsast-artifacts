## 1. Что сканировали

**Датасет:** NIST Juliet Test Suite for C/C++ v1.3
**Количество тест-кейсов:** 64,099
**Количество файлов:** 106.077 `.c` / `.cpp` файлов
**Языки программирования:** C, C++
**Количество CWE директорий:** 118

**Присутствующие CWE:**
- CWE-114: Process Control
- CWE-121: Stack Based Buffer Overflow
- CWE-122: Heap Based Buffer Overflow
- CWE-123: Write What Where Condition
- CWE-124: Buffer Underwrite
- CWE-126: Buffer Overread
- CWE-127: Buffer Underread
- CWE-134: Uncontrolled Format String
- CWE-176: Improper Handling of Unicode Encoding
- CWE-190: Integer Overflow
- CWE-191: Integer Underflow
- CWE-194: Unexpected Sign Extension
- CWE-195: Signed to Unsigned Conversion Error
- CWE-196: Unsigned to Signed Conversion Error
- CWE-197: Numeric Truncation Error
- CWE-222: Truncation of Security-relevant Information
- CWE-223: Omission of Security-relevant Information
- CWE-226: Sensitive Information Uncleared Before Release
- CWE-242: Use of Inherently Dangerous Function
- CWE-244: Improper Clearing of Heap Memory Before Release
- CWE-247: Reliance on DNS Lookups in a Security Decision
- CWE-252: Unchecked Return Value
- CWE-253: Incorrect Check of Function Return Value
- CWE-256: Plaintext Storage of Password
- CWE-259: Hard Coded Password
- CWE-272: Least Privilege Violation
- CWE-273: Improper Check for Dropped Privileges
- CWE-284: Improper Access Control
- CWE-319: Cleartext Transmission of Sensitive Information
- CWE-321: Hard Coded Cryptographic Key
- CWE-325: Missing Required Cryptographic Step
- CWE-327: Use of Broken or Risky Cryptographic Algorithm
- CWE-328: Reversible One-Way Hash
- CWE-336: Same Seed in PRNG
- CWE-337: Predictable Seed in PRNG
- CWE-338: Use of Cryptographically Weak PRNG
- CWE-364: Signal Handler Race Condition
- CWE-369: Divide by Zero
- CWE-377: Insecure Temporary File
- CWE-390: Detection of Error Condition Without Action
- CWE-391: Unchecked Error Condition
- CWE-396: Declaration of Catch for Generic Exception
- CWE-397: Declaration of Throws for Generic Exception
- CWE-398: Indicator of Poor Code Quality
- CWE-400: Uncontrolled Resource Consumption
- CWE-401: Missing Release of Memory after Effective Lifetime
- CWE-404: Improper Resource Shutdown or Release
- CWE-415: Double Free
- CWE-416: Use After Free
- CWE-426: Untrusted Search Path
- CWE-427: Uncontrolled Search Path Element
- CWE-457: Use of Uninitialized Variable
- CWE-464: Addition of Data Structure Sentinel
- CWE-467: Use of sizeof() on a Pointer Type
- CWE-468: Incorrect Pointer Scaling
- CWE-469: Use of Pointer Subtraction to Determine Size
- CWE-475: Undefined Behavior for Input to API
- CWE-476: NULL Pointer Dereference
- CWE-478: Missing Default Case in Switch
- CWE-479: Signal Handler Use of a Non-reentrant Function
- CWE-480: Use of Incorrect Operator
- CWE-481: Assigning Instead of Comparing
- CWE-482: Comparing Instead of Assigning
- CWE-483: Incorrect Block Delimitation
- CWE-484: Omitted Break Statement in Switch
- CWE-506: Embedded Malicious Code
- CWE-510: Trapdoor
- CWE-511: Logic/Time Bomb
- CWE-526: Cleartext Storage of Sensitive Information in an Environment Variable
- CWE-534: Information Exposure Through Debug Log Files
- CWE-535: Information Exposure Through Shell Error Message
- CWE-546: Suspicious Comment
- CWE-561: Dead Code
- CWE-562: Return of Stack Variable Address
- CWE-563: Assignment to Variable Without Use
- CWE-570: Expression is Always False
- CWE-571: Expression is Always True
- CWE-587: Assignment of Fixed Address to Pointer
- CWE-588: Attempt to Access Child of Non-structure Pointer
- CWE-590: Free Memory Not on Heap
- CWE-591: Sensitive Data Storage in Improperly Locked Memory
- CWE-605: Multiple Binds to the Same Port
- CWE-606: Unchecked Loop Condition
- CWE-617: Reachable Assertion
- CWE-620: Unverified Password Change
- CWE-665: Improper Initialization
- CWE-666: Operation on Resource in Wrong Phase of Lifetime
- CWE-667: Improper Locking
- CWE-672: Operation on a Resource after Expiration or Release
- CWE-674: Uncontrolled Recursion
- CWE-675: Duplicate Operations on Resource
- CWE-676: Use of Potentially Dangerous Function
- CWE-680: Integer Overflow to Buffer Overflow
- CWE-681: Incorrect Conversion Between Numeric Types
- CWE-685: Function Call With Incorrect Number of Arguments
- CWE-688: Function Call With Incorrect Variable or Reference as Argument
- CWE-690: NULL Deref From Return
- CWE-758: Reliance on Undefined, Unspecified, or Implementation-Defined Behavior
- CWE-761: Free of Pointer not at Start of Buffer
- CWE-762: Mismatched Memory Management Routines
- CWE-773: Missing Reference to Active File Descriptor or Handle
- CWE-775: Missing Release of File Descriptor or Handle after Effective Lifetime
- CWE-780: Use of RSA Algorithm Without OAEP
- CWE-785: Use of Path Manipulation Function Without Maximum-sized Buffer
- CWE-789: Uncontrolled Memory Allocation
- CWE-832: Unlock of a Resource That is Not Locked
- CWE-833: Deadlock
- CWE-835: Infinite Loop
- CWE-843: Type Confusion

## 2. Чем сканировали

**Анализаторы, которые использовались:**
1. **OpenGrep**
2. **Semgrep**
3. **PVS-Studio**
4. **Joern**
5. **CodeQL**
    
**Анализаторы, которые не удалось использовать:**

1. **PMD**
    - Причина: В PMD нет полноценного парсера для C++ 
2. **SonarQube Scanner**
    - Причина: SonarQube Community Edition не умеет анализировать C/C++

**Итог по выбору:**

- Для сканирования Juliet С/C++ Suite использовались: OpenGrep, Semgrep, PVS, CodeQL, Joern

## 3. Как сканировали

### Скрипты сканирования

#### 3.1 OpenGrep 

Запуск сканирования 

```bash
bash run_opengrep.sh
```

### Что делает скрипт

```bash
#!/usr/bin/env bash
set -euo pipefail

TESTCASES_DIR="./testcases"
REPORTS_DIR="./opengrep_reports"
RULES_DIR="./opengrep_rules/c"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# SARIF report
opengrep scan \
  --config "$RULES_DIR" \
  --include "*.c" --include "*.cpp" --include "*.h" \
  --sarif \
  --output "$REPORTS_DIR/report_${TIMESTAMP}.sarif" \
  "$TESTCASES_DIR" || true

# JSON report
opengrep scan \
  --config "$RULES_DIR" \
  --include "*.c" --include "*.cpp" --include "*.h" \
  --json \
  --output "$REPORTS_DIR/report_${TIMESTAMP}.json" \
  "$TESTCASES_DIR" || true
```

### Результат сканирования

```
Rules run       : 16
Files scanned   : 58 980 (git-tracked)
Findings        : 48 774
```

### Findings по правилам

| Правило | Findings |
|---|---|
| `insecure-use-memset` | 27 520 |
| `insecure-use-string-copy-fn` | 8 415 |
| `incorrect-use-ato-fn` | 6 764 |
| `insecure-use-strcat-fn` | 5 763 |
| `function-use-after-free` | 180 |
| `insecure-use-scanf-fn` | 102 |
| `insecure-use-gets-fn` | 18 |
| `double-free` | 12 |


#### 3.2 Semgrep 

Запуск сканирования (`run_semgrep.sh`)

```bash
bash run_semgrep.sh
```


### Что делает скрипт

Запускает Semgrep дважды — для JSON и текстового отчёта:

```bash
#!/usr/bin/env bash
set -euo pipefail

TESTCASES_DIR="./testcases"
REPORTS_DIR="./semgrep_reports"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

mkdir -p "$REPORTS_DIR"

CONFIGS=("p/c" "p/default" "p/security-audit")

CONFIG_ARGS=()
for cfg in "${CONFIGS[@]}"; do
  CONFIG_ARGS+=(--config "$cfg")
done

# JSON report
semgrep \
  "${CONFIG_ARGS[@]}" \
  --include "*.c" --include "*.cpp" --include "*.h" \
  --json \
  --output "$REPORTS_DIR/report_${TIMESTAMP}.json" \
  "$TESTCASES_DIR" || true

# Text report
semgrep \
  "${CONFIG_ARGS[@]}" \
  --include "*.c" --include "*.cpp" --include "*.h" \
  --output "$REPORTS_DIR/report_${TIMESTAMP}.txt" \
  "$TESTCASES_DIR" || true
```

### Наборы правил

| Набор | Описание |
|---|---|
| `p/c` | Базовые правила для C: `strcpy`, `strcat`, `gets`, `double-free` |
| `p/default` | Общий набор по умолчанию |
| `p/security-audit` | Расширенный аудит безопасности |


#### 3.3 PVS-Studio

### Запуск сканирования

```bash
python run_pvs_studio.py
```

### Что делает скрипт

```python
#!/usr/bin/env python3
import subprocess, os

PVS = "pvs-studio-analyzer"
CONVERTER = "plog-converter"
TESTCASES = "C/testcases"
SUPPORT = "C/testcasesupport"
OUTPUT_DIR = "pvs_results"

# Шаг 1: Трассировка компиляции
subprocess.run([
    PVS, "trace", "--",
    "gcc", "-c", "-w",
    f"-I{TESTCASES}", f"-I{SUPPORT}",
    f"{TESTCASES}/CWE484_Omitted_Break_Statement_in_Switch/*.c",
    f"{TESTCASES}/CWE789_Uncontrolled_Mem_Alloc/s01/*.c"
])

# Шаг 2: Анализ
subprocess.run([
    PVS, "analyze",
    "--output-file", f"{OUTPUT_DIR}/pvs_report.log",
    "--rules-config", "pvs_rules.cfg",
    "--exclude-path", "testcasesupport"
])

# Шаг 3: Конвертация в SARIF
subprocess.run([
    CONVERTER,
    "-t", "sarif",
    "-o", f"{OUTPUT_DIR}/pvs_studio_results.sarif",
    f"{OUTPUT_DIR}/pvs_report.log"
])
```

### Конфигурация правил (`pvs_rules.cfg`)

```ini
[CWE-484 Omitted Break in Switch]
; V796 — A case without a break/return/goto/continue
V796=true
; V797 — The 'default' case is not the last one in the switch
V797=true

[CWE-789 Uncontrolled Memory Allocation]
; V630 — The 'malloc' function allocates memory for an object
;         whose size is specified as 0
V630=true
; V631 — The size of the allocated memory is not a multiple of
;         the element size
V631=true
; V632 — Suspicious use of 'realloc'
V632=true
; V769 — The pointer in the expression equals nullptr
V769=true
```


#### 3.4 CodeQL

### Запуск сканирования

```bash
# Шаг 1: Создание базы данных
codeql database create codeql-db \
  --language=cpp \
  --command="codeql_build.bat" \
  --source-root="C/testcases"

# Шаг 2: Анализ стандартными запросами
codeql database analyze codeql-db \
  cpp-security-and-quality.qls \
  --format=sarif-latest \
  --output=codeql_results_full.sarif

# Шаг 3: Анализ кастомными запросами
codeql database analyze codeql-db \
  custom_queries/ \
  --format=sarif-latest \
  --output=codeql_custom_results.sarif
```

### Что делает скрипт

```powershell
# codeql_build.bat — компиляция тесткейсов
set GCC=C:\msys64\ucrt64\bin\gcc.exe
set SRC=%~dp0C\testcases

for /r "%SRC%\CWE484_Omitted_Break_Statement_in_Switch" %%f in (*.c) do (
    "%GCC%" -c -w -I"%SRC%" -I"%SUPPORT%" "%%f" -o "%%f.o"
)
for /r "%SRC%\CWE789_Uncontrolled_Mem_Alloc\s01" %%f in (*.c) do (
    "%GCC%" -c -w -I"%SRC%" -I"%SUPPORT%" "%%f" -o "%%f.o"
)
```

### Findings по правилам

| Правило | Findings |
|---|---|
| Все стандартные запросы (182) | 0 |
| `CWE484_MissingBreak.ql` (кастомный) | 0 |
| `CWE789_UncontrolledAlloc.ql` (кастомный) | 0 |

### Кастомные запросы

**CWE-484 — поиск fall-through в switch:**

```ql
/**
 * @name Missing break in switch case
 * @id cpp/cwe484-missing-break
 * @kind problem
 * @problem.severity warning
 * @tags security cwe-484
 */
import cpp

from SwitchCase sc
where
  not exists(BreakStmt bs | bs.getEnclosingStmt*() = sc) and
  not exists(ReturnStmt rs | rs.getEnclosingStmt*() = sc) and
  not exists(GotoStmt gs | gs.getEnclosingStmt*() = sc) and
  exists(sc.getNextSwitchCase())
select sc, "CWE-484: Missing break statement - falls through to next case"
```

**CWE-789 — taint-анализ неконтролируемого размера malloc:**

```ql
/**
 * @name Uncontrolled memory allocation
 * @id cpp/cwe789-uncontrolled-alloc
 * @kind path-problem
 * @problem.severity error
 * @tags security cwe-789
 */
import cpp
import semmle.code.cpp.dataflow.TaintTracking

class JulietSource extends DataFlow::Node {
  JulietSource() {
    exists(FunctionCall fc |
      fc.getTarget().getName() in
        ["fgets", "fscanf", "recv", "recvfrom", "strtoul", "atoi", "rand"] and
      this.asExpr() = fc
    )
  }
}

class MallocSink extends DataFlow::Node {
  MallocSink() {
    exists(FunctionCall fc |
      fc.getTarget().getName() = "malloc" and
      this.asExpr() = fc.getArgument(0)
    )
  }
}

from JulietSource source, MallocSink sink
where TaintTracking::localTaint(source, sink)
select sink, source, sink,
  "CWE-789: Uncontrolled allocation size from $@", source, "external input"
```

#### 3.5 Joern 

### Запуск сканирования

```bash
python run_joern_analysis.py
```

### Что делает скрипт

```python
# Импортирует тесткейсы в CPG
joern.importCode("C/testcases", projectName="juliet_cpg")

# Запрос CWE-484: switch без break
val cwe484 = cpg.controlStructure
  .controlStructureType("SWITCH")
  .flatMap { sw =>
    val cases = sw.astChildren.isControlStructure
      .controlStructureType("CASE|DEFAULT").l
      .sortBy(_.lineNumber.getOrElse(0))
    cases.zipWithIndex.flatMap { case (c, i) =>
      val hasExit = c.ast.isControlStructure
        .controlStructureType("BREAK|RETURN|GOTO|CONTINUE").nonEmpty
      if (!hasExit && i < cases.length - 1) Some(c) else None
    }
  }.l

# Запрос CWE-789: malloc с внешним источником
val cwe789 = cpg.call.name("malloc|calloc|realloc")
  .filter { call =>
    call.method.ast.isCall
      .name("fgets|fscanf|recv|recvfrom|strtoul|atoi|scanf|read")
      .nonEmpty
  }.l
```
### Findings по правилам

| Правило | Findings |
|---|---|
| `CWE789-uncontrolled-memory-allocation` | 472 |
| `CWE484-omitted-break-in-switch` | 0 |

## 4. Результаты анализа каждого анализатора

### 4.1 OpenGrep

| Метрика | Значение |
|---|---|
| Total findings | 48 774 |
| TP | 3 721 |
| FP | 40 957 |
| TN | 85 893 |
| FN | 23 969 |
| CWE dirs с TP | 26 / 118 |
| Precision | 0.0833 |
| Recall | 0.1344 |
| Specificity | 0.6771 |
| F1 | 0.1028 |




### 4.2 Semgrep

| Метрика | Значение |
|---|---|
| Total findings | 14 310 |
| TP | 503 |
| FP | 12 454 |
| TN | 112 077 |
| FN | 27 187 |
| CWE dirs с TP | 13 / 118 |
| Precision | 0.0388 |
| Recall | 0.0182 |
| Specificity | 0.9000 |
| F1 | 0.0247 |




### 4.3 PVS-Studio

| Метрика | Значение |
|---|---|
| Total findings | 35 525 |
| TP | 1 372 |
| FP | 12 151 |
| TN | 716 719 |
| FN | 12 151 |
| Precision | 0.101457 |
| Recall | 0.101457 |
| Specificity | 0.983329 |
| F1 | 0.101457 |


### 4.4 CodeQL

| Метрика | Значение |
|---|---|
| Total findings | 0 |
| TP | 0 |
| FP | 0 |
| TN | 124 531 |
| FN | 32 130 |
| CWE dirs с TP | 0 / 118 |
| Precision | 0.0000 |
| Recall | 0.0000 |
| Specificity | 1.0000 |
| F1 | 0.0000 |

#### Технические причины нулевого результата 

Условная компиляция Juliet скрывает уязвимый код**

Juliet специально оборачивает весь уязвимый код в препроцессорные директивы:

```c
#ifndef OMITBAD
void CWE484_..._bad() {
    switch (x) {
    case 0:
        printLine("0");   // уязвимость — нет break
    case 1: ...
    }
}
#endif
```c

#### 4.5 Joern

| Метрика | Значение |
|---|---|
| Total findings | 472 |
| TP | 176 |
| FP | 294 |
| TN | 124 237 |
| FN | 31 954 |
| CWE dirs с TP | 1 / 118 |
| Precision | 0.3745 |
| Recall | 0.0055 |
| Specificity | 0.9976 |
| F1 | 0.0108 |
