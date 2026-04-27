# IAMeter: отчёты и как их получать

Исходники бенчмарка в корне репозитория приложения: `IAMeter_Go/`, `IAMeter_Java/`, `IAMeter_PHP/`.  
В подкаталогах `go/`, `java/`, `php/` лежат копии **SARIF** (и пр.) для сравнения; команды ниже выполняйте из **соответствующего** каталога бенчмарка или указывайте путь к нему.

Общие переменные (пример):

- `SONAR_HOST_URL` — URL SonarQube (например `http://localhost:9000`)
- `SONAR_TOKEN` — токен пользователя SonarQube
- `SONAR_KEY` / `sonar.projectKey` в `sonar-project.properties` — должны совпадать с проектом в SonarQube

---

## Semgrep → SARIF

```bash
cd <project>
semgrep scan --config auto --sarif --output semgrep.sarif .
```

---

## OpenGrep → SARIF

```bash
cd <project>
opengrep scan --sarif --output opengrep.sarif .
```

(Синтаксис флагов может отличаться по версии; главное — итоговый формат **SARIF 2.1.0**.)

---

## CodeQL → SARIF

**Go**

```bash
cd IAMeter_Go
codeql database create ./codeql-go --language=go --command="go build -o /dev/null ."
codeql database analyze ./codeql-go --format=sarifv2.1.0 --output=codeql-results.sarif
```

**Java** (нужен собранный класспас; для Maven: `mvn -q compile`)

```bash
cd IAMeter_Java
codeql database create ./codeql-java --language=java --command="mvn -q compile"
codeql database analyze ./codeql-java --format=sarifv2.1.0 --output=codeql-results.sarif
```

Пакеты запросов укажите сами (например `java-security-and-quality.qls` / наборы для Go), в зависимости от установленного CodeQL.

---

## SonarQube → SARIF

1. В каталоге бенчмарка (где лежит `sonar-project.properties`):

   ```bash
   sonar-scanner \                    23:02:00
      -Dsonar.projectKey=<your-key> \
      -Dsonar.sources=<path> \
      -Dsonar.host.url=http://localhost:9000 \
      -Dsonar.token=<token>
   ```

2. Вытянуть issues из API и собрать SARIF.

---

## PMD (только Java) → SARIF

```bash
cd IAMeter_Java
mvn -q compile
pmd check -R category/java/security.xml -d src/main/java -f sarif -r pmd-report.sarif
```

Или через Maven PMD plugin с форматом `sarif`.

---

## PVS-Studio (только Java) → JSON, затем SARIF


```bash
sh help-tools/pvs_iameter_java_per_file.sh
```

В SARIF (для DefectDojo и т.п.): утилита **plog-converter** (поставляется с PVS-Studio), например:

```bash
plog-converter -t sarif -o pvs-iameter.sarif pvs_project_report.json
```

---

## Joern → текст, затем SARIF

1. Скан (три проекта):

   ```bash
   sh help-tools/joern_iameter_all.sh
   ```

   Создаётся `joern-scan.txt` в каждом `IAMeter_*` (строки `Result: ...`).

2. Конвертация в SARIF:

   ```python
   python3 help-tools/joern_scan_txt_to_sarif.py --root .
   ```

   (из корня репозитория приложения, где лежат `IAMeter_Go` и т.д.)

Нативного SARIF у `joern-scan` в выводе обычно нет; используется конвертер по текстовому логу.

---

