# Scanning IAMeter Repositories

## Scope of Scanning

Three repositories from the Positive Technologies organization were selected:

- IAMeter_Go
- IAMeter_Java
- IAMeter_PHP

They are written in Go, Java, and PHP respectively.

### IAMeter_Go

- Lines of code: **450**
- Number of files: **10**
- CWE coverage: 2 types: **CWE-79** (Cross-site Scripting / XSS, *Improper Neutralization of Input During Web Page Generation*) and **CWE-611** (XXE, *Improper Restriction of XML External Entity Reference*)

### IAMeter_Java

- Lines of code: **334**
- Number of files: **10**
- CWE coverage: 2 types: **CWE-79** (Cross-site Scripting / XSS, *Improper Neutralization of Input During Web Page Generation*) and **CWE-611** (XXE, *Improper Restriction of XML External Entity Reference*)

### IAMeter_PHP

- Lines of code: **256**
- Number of files: **10**
- CWE coverage: 2 types: **CWE-79** (Cross-site Scripting / XSS, *Improper Neutralization of Input During Web Page Generation*) and **CWE-611** (XXE, *Improper Restriction of XML External Entity Reference*)

## Analyzer Usage

Each repository used its own analyzer scope. This is because some analyzers do not support every programming language used in the benchmark.

The table below shows which analyzer scanned each project, according to the rows in `total.csv` / CompSAST, and where a tool was not included in the set or was intended for only one language.

| Analyzer | IAMeter_Go | IAMeter_Java | IAMeter_PHP |
| ---------- | ---------- | ------------ | ----------- |
| **Semgrep** | yes | yes | yes |
| **OpenGrep** | yes | yes | yes |
| **CodeQL** | yes | yes | no |
| **SonarQube** | yes | yes | yes |
| **PMD** | no* | yes | no* |
| **PVS-Studio** | no | yes | no |
| **Joern** (joern-scan) | yes | yes | yes |

* For `Go` and `PHP`, **PMD** supports only `CPD`, the copy-paste detector.

All analyzers except **PVS-Studio** scanned each project as a whole. Due to the specifics of its operation, and to obtain more accurate results, **PVS-Studio** scanned the project file by file.

## Analysis Process and Helper Scripts

### Semgrep

This analyzer was run with the following command:

```bash
semgrep scan --config auto --sarif --output=results.sarif
```

### OpenGrep

This analyzer was run with the following command:

```bash
opengrep scan --sarif-output=output.sarif
```

### CodeQL

To scan with this analyzer, a database must first be created:

```bash
codeql database create <db-name> --language=<lang> --source-root <path-to-root>
```

Then the analysis is run:

```bash
codeql database analyze <db-name> \
  --format=sarifv2.1.0 \
  --output=<output-name>.sarif \
  codeql/java-queries:codeql-suites/java-security-and-quality.qls # Add the rule set for the specific programming language here
```

### SonarQube

First, **SonarQube** had to be deployed locally. This was done with Docker:

```bash
docker run -d --name sonarqube -p 9000:9000 sonarqube:community
```

Then projects for the repositories were created in SonarQube. After that, sonar-scanner had to be downloaded and the analysis was run:

```bash
cd project

sonar-scanner \
  -Dsonar.projectKey=<project-key> \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=<sonar-token>
```

After that, issues were exported from the SonarQube server to `SARIF` using the `compsast-artifacts/sonar_issues_to_sarif.py` script. The script works as follows:
- It sends HTTPS requests to `/api/issues/search` with pagination, open issues, and `componentKeys=<projectKey>`.
- It builds `runs[0].results` with file paths and line ranges; `properties` contains the issue key, type, Sonar severity, and other available API fields.
- The token and URL are passed through flags or through `SONAR_TOKEN`, `SONAR_HOST_URL`, and `SONAR_PROJECT_KEY`.

Example:

```bash
export SONAR_TOKEN=<sonar-token>
python3 compsast-artifacts/sonar_issues_to_sarif.py \
  --host http://localhost:9000 \
  --project-key <project-key> \
  -o sonarqube.sarif
```

### PMD

This analyzer was run with the following command:

```bash
pmd check --dir ./src --rulesets category/java/security.xml  --format sarif --report-file pmd-report.sarif
```

### PVS-Studio

`pvs_iameter_java_per_file.sh` sequentially runs PVS-Studio Java on each file in `IAMeter_Java/src/main/java/iameter/*.java`, writes a separate JSON report for each file to `pvs-by-file/`, and then calls **`merge_pvs_json_reports.py`**, which merges these reports into a single `pvs_project_report_per_file.json`. After that, **plog-converter** from the PVS distribution converts the final JSON report to SARIF:

```bash
plog-converter -t sarif -o pvs-iameter.sarif pvs_project_report_per_file.json
```

### Joern

Scanning was performed by the `compsast-artifacts/joern_iameter_all.sh` script. It runs `joern-scan` three times from the repository root: separately for *IAMeter_Go*, *IAMeter_Java*, and *IAMeter_PHP*; each run contains files from only one language. Before the Java run, `mvn -q compile` is executed. The output of each run is written next to the project as `IAMeter_*/joern-scan.txt`. Then `joern_scan_txt_to_sarif.py` is executed to build `IAMeter_*/joern-scan.sarif`. Language keys are set through the **`JOERN_LANG_*`** variables or default to `golang`, `java`, and `php`.

## Scan Results

The table below summarizes which CWE categories the tools found after SARIF matching. The *"-"* marker means that the analyzer was not run for the language of that repository.

| Analyzer | IAMeter_Java | IAMeter_Go | IAMeter_PHP |
| ----------- | ----------- | --------- | --------- |
| **Semgrep** | CWE-79 and CWE-611 | CWE-79 | not found |
| **OpenGrep** | CWE-79 and CWE-611 | CWE-79 | not found |
| **CodeQL** | CWE-79 | not found | - |
| **SonarQube** | not found | - | not found |
| **PMD** | not found | - | - |
| **PVS-Studio** | not found | - | - |
| **Joern** | not found | not found | not found |
