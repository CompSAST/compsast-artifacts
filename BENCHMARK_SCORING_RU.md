# Принцип работы `benchmark_sarif.py`

Этот документ описывает, как скрипт `benchmark_sarif.py` считает метрики для SARIF-результатов Semgrep/OpenGrep на Juliet C# test suite.

## Общая идея

Скрипт сравнивает реальные сработки анализатора из SARIF с ожидаемыми маркерами в Juliet-коде.

Juliet содержит два типа путей:

- `Bad*` - уязвимый код, где анализатор должен найти проблему.
- `Good*` - безопасный код, где анализатор не должен ругаться.

Текущая версия скрипта использует **line-aware scoring**: единица оценки не весь файл и не весь метод, а конкретная строка с Juliet-маркером.

## Как строится ground truth

Скрипт проходит по `src/testcases/**/*.cs` и делает несколько шагов.

1. Парсит header файла:

```csharp
* CWE: 23 Relative Path Traversal
* Flow Variant: 07 ...
* Template File: sources-sink-07.tmpl.cs
```

Из header берутся:

- `cwe_id`;
- `cwe_name`;
- `flow_variant`;
- `template_file`.

2. Находит методы Juliet:

```csharp
Bad()
BadSink()
GoodG2B()
GoodB2G()
GoodG2BSink()
GoodB2GSink()
```

Методы `Bad*` считаются bad-регионами. Методы `Good*` считаются good-регионами.

3. Внутри этих методов ищет строки с маркерами:

```csharp
/* FLAW */
/* POTENTIAL FLAW */
/* FIX */
```

## Vulnerable points

`vulnerable point` - это строка внутри `Bad*`-метода, где есть:

```csharp
/* FLAW */
```

или:

```csharp
/* POTENTIAL FLAW */
```

Именно эти строки считаются местами, где анализатор должен показать finding.

Пример:

```csharp
/* POTENTIAL FLAW: no validation of concatenated value */
if (File.Exists(root + data))
```

Если анализатор попал в эту строку или рядом с ней, это засчитывается как обнаружение.

## Safe points

`safe point` - это строка внутри `Good*`-метода, где есть:

```csharp
/* FIX */
```

или безопасный decoy:

```csharp
/* POTENTIAL FLAW */
```

Почему `POTENTIAL FLAW` внутри `Good*` считается safe point: в Juliet часто сохраняется потенциально опасный sink, но путь данных безопасный.

Например:

```csharp
/* FIX: Use a hardcoded string */
data = "foo";

/* POTENTIAL FLAW: no validation of concatenated value */
if (File.Exists(root + data))
```

Sink выглядит опасно, но source безопасный. Поэтому анализатор не должен ругаться на этот путь.

## Как считается TP

`TP` - true positive.

Finding считается `TP`, если он попал рядом с `vulnerable point`.

По умолчанию используется окно:

```text
--line-window 3
```

То есть finding может быть на строке `FLAW` или на расстоянии до 3 строк от нее.

Формально:

```text
finding.file == vulnerable_point.file
abs(finding.line - vulnerable_point.line) <= line_window
```

Если включен `--cwe-aware`, дополнительно должен совпасть CWE finding-а и expected CWE тесткейса.

## Как считается FN

`FN` - false negative.

Каждый `vulnerable point`, рядом с которым не оказалось finding-а, считается `FN`.

Формула:

```text
FN = vulnerable points without matched finding
```

Проверка:

```text
TP + FN = total_vulnerable_points
```

## Как считается FP

`FP` - false positive.

В текущей line-aware модели FP состоит из двух частей.

### 1. Finding рядом с safe point

Если finding попал рядом с `safe point`, это `FP`.

Пример:

```csharp
/* FIX: Use a hardcoded string */
data = "foo";
```

Если анализатор ругается на эту строку или рядом, это false positive.

### 2. Unmatched finding

Если finding попал в testcase-код, но не попал рядом ни с одним `vulnerable point`, он считается `unmatched_fp`.

Для итоговой матрицы `unmatched_fp` добавляется к `FP`.

Это нужно, чтобы анализатор не получал TP за сработку "где-то в плохом методе", если он не указал на ожидаемую Juliet flaw-line.

Пример:

```text
Juliet testcase: CWE113 HTTP Response Splitting
Finding: BinaryFormatter warning
Finding line: не рядом с Juliet FLAW line
Classification: unmatched_fp
```

## Как считается TN

`TN` - true negative.

Каждый `safe point`, рядом с которым не оказалось finding-а, считается `TN`.

Формула:

```text
TN = safe points without matched finding
```

Проверка:

```text
FP_from_safe_points + TN = total_safe_points
```

Важно: `unmatched_fp` добавляется к общему `FP`, но не уменьшает `TN`, потому что `TN` считается только по конкретным safe points.

## Основные поля summary CSV

Файл:

```text
results/<tool>_eval/<tool>_summary.csv
```

Поля:

```text
tp
```

Количество finding-ов, попавших в ожидаемые уязвимые строки.

```text
fn
```

Количество ожидаемых уязвимых строк без finding-а.

```text
fp
```

Количество false positive. Включает:

- finding рядом с safe point;
- `unmatched_fp_findings`.

```text
tn
```

Количество safe points без finding-а.

```text
total_vulnerable_points
```

Количество `FLAW` / `POTENTIAL FLAW` строк внутри `Bad*`-кода.

```text
total_safe_points
```

Количество `FIX` и safe-decoy `POTENTIAL FLAW` строк внутри `Good*`-кода.

```text
total_findings
```

Общее количество findings из SARIF.

```text
unmatched_fp_findings
```

Количество findings, которые не попали рядом с ожидаемой уязвимой строкой.

```text
unknown_findings
```

Findings, которые не удалось привязать к распознанному Juliet-методу.

```text
out_of_scope_findings
```

Findings, которые отброшены в `--cwe-aware` режиме из-за несовпадения CWE.

## Метрики

```text
precision = TP / (TP + FP)
```

Доля корректных сработок среди всех сработок, засчитанных в матрицу.

```text
recall = TP / (TP + FN)
```

Доля найденных уязвимых точек.

```text
specificity = TN / (TN + FP)
```

Доля безопасных точек, на которые анализатор не ругался.

```text
f1 = 2 * precision * recall / (precision + recall)
```

Гармоническое среднее precision и recall.

## Отличие от старого region-based подхода

Раньше скрипт считал единицей оценки весь метод:

```text
finding внутри Bad()   -> TP
finding внутри Good*() -> FP
Bad() без finding      -> FN
Good*() без finding    -> TN
```

Это завышало TP: finding мог быть внутри `Bad()`, но не на той строке и не по той проблеме.

Сейчас используется line-aware подход:

```text
finding рядом с FLAW в Bad* -> TP
FLAW в Bad* без finding     -> FN
finding рядом с FIX/Good*   -> FP
safe point без finding      -> TN
```

Такой подход ближе к интуиции "анализатор должен указать конкретное место уязвимости".

## Ограничения методики

1. Juliet-маркеры не всегда идеально соответствуют тому месту, куда реальный SAST ставит finding.

Некоторые анализаторы указывают source, другие sink, третьи начало выражения или метода. Для этого есть `--line-window`.

2. `POTENTIAL FLAW` внутри `Good*` не является настоящей уязвимостью.

Скрипт учитывает это и считает такие строки safe points.

3. Без `--cwe-aware` скрипт не проверяет, совпал ли CWE правила с CWE тесткейса.

Для строгого сравнения нужен mapping:

```csv
rule_id,cwe
csharp.lang.security.path-traversal,CWE23
```

И запуск:

```bash
python3 benchmark_sarif.py \
  --src src/testcases \
  --sarif sarif/opengrep.sarif \
  --tool opengrep \
  --out-dir results/opengrep_eval \
  --cwe-aware \
  --rule-cwe-map rules_cwe_map.csv
```

4. `TN` в SAST-бенчмарках всегда условная метрика.

Здесь `TN` считается не по всем строкам кода, а только по Juliet safe points. Это делает число осмысленным и не раздувает его до количества всех безопасных строк.

## Полезные debug-файлы

```text
<tool>_points.csv
```

Главный файл для проверки line-aware ground truth. Одна строка = один vulnerable/safe point.

```text
<tool>_findings.csv
```

Одна строка = один finding из SARIF с классификацией.

```text
<tool>_regions.csv
```

Диапазоны `Bad*` / `Good*` методов. Используется как контекст, но не является основной единицей оценки.

```text
<tool>_by_cwe.csv
```

TP/FP/TN/FN и метрики по каждой CWE.
