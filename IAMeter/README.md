# Сканирование IAMeter репозиториев

## Область сканирования 

Было взято 3 репозитория от организации Positive Technologies:

- IAMeter_Go
- IAMeter_Java
- IAMeter_PHP

Написанных на Go, Java и PHP соответственно.

### IAMeter_Go

- Количество строк кода: **450** 
- Количество файлов: **10** 
- CWE: 2 вида — **CWE-79** (Cross-site Scripting / XSS, *Improper Neutralization of Input During Web Page Generation*) и **CWE-611** (XXE, *Improper Restriction of XML External Entity Reference*)

### IAMeter_Java

- Количество строк кода: **334** 
- Количество файлов: **10**
- CWE: 2 вида — **CWE-79** (Cross-site Scripting / XSS, *Improper Neutralization of Input During Web Page Generation*) и **CWE-611** (XXE, *Improper Restriction of XML External Entity Reference*)

### IAMeter_PHP

- Количество строк кода: **256** 
- Количество файлов: **10**
- CWE: 2 вида — **CWE-79** (Cross-site Scripting / XSS, *Improper Neutralization of Input During Web Page Generation*) и **CWE-611** (XXE, *Improper Restriction of XML External Entity Reference*)

## Использование анализаторов

Для каждого репозитория использовался свой определенный scope анализаторов. Связано это с тем, что у некоторых анализаторов отсутствует поддержка того или иного языка программирования.

Ниже представлена таблица, в которой видно, какой анализатор сканировал тот или иной проект (по строкам в `total.csv` / CompSAST), а где инструмент в этот набор не входил или ориентирован только на один язык.

| Анализатор | IAMeter_Go | IAMeter_Java | IAMeter_PHP |
| ---------- | ---------- | ------------ | ----------- |
| **Semgrep** | да | да | да |
| **OpenGrep** | да | да | да |
| **CodeQL** | да | да | нет |
| **SonarQube** | да | да | да |
| **PMD** | нет* | да | нет* |
| **PVS-Studio** | нет | да | нет |
| **Joern** (joern-scan) | да | да | да |

* **PMD** в языках `Go`, `PHP` поддерживает только `CPD` - the copy-paste-detector.

Все анализаторы, кроме **PVS-Studio** сканировали проект полностью. Из-за специфики работы и для получения более точных результатов, **PVS-Studio** сканировал проект пофайлово.

## Процесс анализа. Вспомогательные скрипты

### Semgrep

Сканировался данный анализатор следующей командой:

```bash
semgrep scan --config auto --sarif --output=results.sarif
```

### Opengrep

Сканировался данный анализатор следующей командой:

```bash
opengrep scan --sarif-output=output.sarif
```

### CodeQL

Для сканирования данным анализатором сначала нужно создать базу данных:

```bash
codeql database create <db-name> --language=<lang> --source-root <path-to-root>
```

После чего запускаем анализ:

```bash
codeql database analyze <db-name> \
  --format=sarifv2.1.0 \
  --output=<output-name>.sarif \
  codeql/java-queries:codeql-suites/java-security-and-quality.qls # Сюда добавляется сет рулов под конкретный ЯП
```

### SonarQube

Сначала **SonarQube** нужно было развернуть на машине. Делал я это с помощью Docker:

```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
```

Затем, в SonarQube создать проекты под репозитории.
После чего нужно было скачать sonar-scanner и запустить анализ:

```bash
cd project

sonar-scanner \  
  -Dsonar.projectKey=<project-key> \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<sonar-token>
```

После чего, с помощью скрипта `help-tools/sonar_issues_to_sarif.py`, выгрузка issues с сервера SonarQube в `SARIF`. Как работает скрипт: 
- Делает HTTPS-запросы к `/api/issues/search` (с пагинацией, открытые issues, `componentKeys=<projectKey>`).
- Собирает `runs[0].results` с путями к файлам и диапазонами строк; в `properties` — ключ issue, тип, severity Sonar и т.д. (по возможности из полей API).
- Токен и URL передаются флагами или через `SONAR_TOKEN`, `SONAR_HOST_URL`, `SONAR_PROJECT_KEY`.

Пример:

```bash
export SONAR_TOKEN=<sonar-token>
python3 help-tools/sonar_issues_to_sarif.py \
  --host http://localhost:9000 \
  --project-key <project-key> \
  -o sonarqube.sarif
```

### PMD
Сканировался данный анализатор следующей командой:

```bash
pmd check --dir ./src --rulesets category/java/security.xml  --format sarif --report-file pmd-report.sarif
```

### PVS-Studio

`pvs_iameter_java_per_file.sh` последовательно запускает PVS-Studio Java по каждому файлу `IAMeter_Java/src/main/java/iameter/*.java`, пишет для каждого отдельный JSON в `pvs-by-file/`, затем вызывает **`merge_pvs_json_reports.py`**, который склеивает эти отчёты в один `pvs_project_report_per_file.json`. Дальше **plog-converter** (из дистрибутива PVS) переводит итоговый JSON в SARIF:

```bash
plog-converter -t sarif -o pvs-iameter.sarif pvs_project_report_per_file.json
```

### Joern

Сканирование выполнялось скриптом `help-tools/joern_iameter_all.sh`: он три раза запускает `joern-scan` из корня репозитория — отдельно для *IAMeter_Go*, *IAMeter_Java*, *IAMeter_PHP* (в одном прогоне смешиваются только файлы одного языка). Перед Java-прогоном вызывается `mvn -q compile`. Вывод каждого запуска пишется рядом с проектом в *`IAMeter_*/joern-scan.txt`*; затем выполняется *`joern_scan_txt_to_sarif.py`*, который строит *`IAMeter_*/joern-scan.sarif`*. Языковые ключи задаются переменными **`JOERN_LANG_*`** или по умолчанию (`golang` / `java` / `php`).

## Результаты сканирования

Таблица ниже суммирует, какие **CWE из разметки бенча** (строки *True positive* под CWE-79 или CWE-611) инструменты «нашли» при сопоставлении SARIF с этой разметкой (детали см. в `total.csv`, `java/IAMeter_Java.csv`, `go/IAMeter_Go.csv`, `php/IAMeter_PHP.csv`; перегенерация — `python3 help-tools/IAMeter/sarif_cwe_table_csv.py`). **«Не нашёл»** — ни одна замеченная по разметке уязвимость данного CWE не признана срабатыванием с нужным CWE (порог строки ±2). Ключ **«—»** — анализатор к языку этого репозитория не запускался.

| Анализатор | IAMeter_Java | IAMeter_Go | IAMeter_PHP |
| ----------- | ----------- | --------- | --------- |
| **Semgrep** | CWE-79 и CWE-611 | CWE-79 | не нашёл |
| **OpenGrep** | CWE-79 и CWE-611 | CWE-79 | не нашёл |
| **CodeQL** | CWE-79 (**CWE-611 — не нашёл**) | не нашёл | — |
| **SonarQube** | не нашёл | — | не нашёл |
| **PMD** | не нашёл | — | — |
| **PVS-Studio** | не нашёл | — | — |
| **Joern** | не нашёл | не нашёл | не нашёл |

*В IAMeter_Go для CWE-611 в нашей разметке нет отдельных контрольных точек XXE — в CSV по этому CWE для Go по всем инструментам нули; отражённые в таблице итоги касаются в основном сценария CWE-79 (XSS-строки).*