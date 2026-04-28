## NIST Juliet C#
> by Arsen Galiev (Github: [projacktor](https://github.com/projacktor))

Source: https://samate.nist.gov/SARD/test-suites/110

Benchmark NIST Juliet C# has a following characteristics:
- Name: NIST Juliet C# v. 1.3 by 01.08.2020
- Files (src/testcases) number: 47267
- Code lines: 112339
- Programming language C#
- CWEs: 105 types

Types of CWEs:

| cwe_id | cwe_name |
| --- | --- |
| CWE-15 | External Control of System or Configuration Setting |
| CWE-23 | Relative Path Traversal |
| CWE-36 | Absolute Path Traversal |
| CWE-78 | OS Command Injection |
| CWE-80 | XSS |
| CWE-81 | XSS Error Message |
| CWE-83 | XSS Attribute |
| CWE-89 | SQL Injection |
| CWE-90 | LDAP Injection |
| CWE-94 | Improper Control of Generation of Code |
| CWE-113 | HTTP Response Splitting |
| CWE-114 | Process Control |
| CWE-117 | Improper Output Neutralization for Logs |
| CWE-129 | Improper Validation of Array Index |
| CWE-134 | Externally Controlled Format String |
| CWE-190 | Integer Overflow |
| CWE-191 | Integer Underflow |
| CWE-193 | Off by One Error |
| CWE-197 | Numeric Truncation Error |
| CWE-209 | Information Leak Error |
| CWE-226 | Sensitive Information Uncleared Before Release |
| CWE-248 | Uncaught Exception |
| CWE-252 | Unchecked Return Value |
| CWE-253 | Incorrect Check of Function Return Value |
| CWE-256 | Unprotected Storage of Credentials |
| CWE-259 | Hard Coded Password |
| CWE-261 | Weak Cryptography for Passwords |
| CWE-284 | Improper Access Control |
| CWE-313 | Cleartext Storage in a File or on Disk |
| CWE-314 | Cleartext Storage in the Registry |
| CWE-315 | Cleartext Storage in Cookie |
| CWE-319 | Cleartext Tx Sensitive Info |
| CWE-321 | Hard Coded Cryptographic Key |
| CWE-325 | Missing Required Cryptographic Step |
| CWE-327 | Use Broken Crypto |
| CWE-328 | Reversible One Way Hash |
| CWE-329 | Not Using Random IV with CBC Mode |
| CWE-336 | Same Seed in PRNG |
| CWE-338 | Weak PRNG |
| CWE-350 | Reliance on Reverse DNS Resolution for Security Action |
| CWE-366 | Race Condition within a Thread |
| CWE-369 | Divide by Zero |
| CWE-378 | Temporary File Creation With Insecure Perms |
| CWE-379 | Temporary File Creation in Insecure Dir |
| CWE-390 | Error Without Action |
| CWE-395 | Catch NullPointerException |
| CWE-396 | Catch Generic Exception |
| CWE-397 | Throw Generic Exception |
| CWE-398 | Code Quality |
| CWE-400 | Uncontrolled Resource Consumption |
| CWE-404 | Improper Resource Shutdown |
| CWE-426 | Untrusted Search Path |
| CWE-427 | Uncontrolled Search Path Element |
| CWE-440 | Expected Behavior Violation |
| CWE-459 | Incomplete Cleanup |
| CWE-470 | Unsafe Reflection |
| CWE-476 | NULL Pointer Dereference |
| CWE-477 | Obsolete Functions |
| CWE-478 | Missing Default Case in Switch |
| CWE-481 | Assigning Instead of Comparing |
| CWE-482 | Comparing Instead of Assigning |
| CWE-483 | Incorrect Block Delimitation |
| CWE-486 | Compare Classes by Name |
| CWE-506 | Embedded Malicious Code |
| CWE-510 | Trapdoor |
| CWE-511 | Logic Time Bomb |
| CWE-523 | Unprotected Cred Transport |
| CWE-526 | Info Exposure Environment Variables |
| CWE-532 | Inclusion of Sensitive Info in Log |
| CWE-535 | Info Exposure Shell Error |
| CWE-539 | Information Exposure Through Persistent Cookie |
| CWE-546 | Suspicious Comment |
| CWE-549 | Missing Password Masking |
| CWE-561 | Dead Code |
| CWE-563 | Assign to Variable Without Use |
| CWE-566 | Authorization Bypass Through SQL Primary |
| CWE-570 | Expression Always False |
| CWE-571 | Expression Always True |
| CWE-582 | Array Public Readonly Static |
| CWE-598 | Information Exposure QueryString |
| CWE-601 | Open Redirect |
| CWE-605 | Multiple Binds Same Port |
| CWE-606 | Unchecked Loop Condition |
| CWE-609 | Double Checked Locking |
| CWE-613 | Insufficient Session Expiration |
| CWE-614 | Sensitive Cookie Without Secure |
| CWE-615 | Info Exposure by Comment |
| CWE-617 | Reachable Assertion |
| CWE-643 | Xpath Injection |
| CWE-667 | Improper Locking |
| CWE-674 | Uncontrolled Recursion |
| CWE-675 | Duplicate Operations on Resource |
| CWE-681 | Incorrect Conversion Between Numeric Types |
| CWE-690 | NULL Deref From Return |
| CWE-698 | Execution After Redirect |
| CWE-759 | Unsalted One Way Hash |
| CWE-760 | Predictable Salt One Way Hash |
| CWE-764 | Multiple Locks |
| CWE-765 | Multiple Unlocks |надеюсь
| CWE-772 | Missing Release of Resource |
| CWE-775 | Missing Release of File Descriptor or Handle |
| CWE-789 | Uncontrolled Mem Alloc |
| CWE-832 | Unlock Not Locked |
| CWE-833 | Deadlock |
| CWE-835 | Infinite Loop |

### Which tools were/not used

The benchmark was applied for the following list of SAST tools:

- Semgrep
- Opengrep
- CodeQL
- PVS-Studio

And by the reasons below was not run by SonarQube, PMD and Joern:

- SonarQube was applied, but the test suite size was too large for the tool, therefore several machines on AMD Ryzen 5500U and AMD Ryzen 5600H (16GiB RAM both) could not proceed the scan results and shutdown in process.

- PMD does not support proper C# scanning, only copy-paste-detector (CPD).

- Joern does not support C# language at all.

### Terms:

- `Safe-sink`. In test suite we may have a following code constructions:
```csharp
/* FIX: Use a hardcoded string */
data = "foo";
/* POTENTIAL FLAW: no validation of concatenated value */
if (File.Exists(root + data))
The string POTENTIAL FLAW looks like a dangerous sink, but in this Good* path, the data is already safe: for example, data is specified as a constant, has passed validation, or came from a safe source.
```
Therefore, for the script:
    - POTENTIAL FLAW in a `Bad*` method -> vulnerable point;
    - POTENTIAL FLAW in a `Good*` method -> safe point, i.e., safe-sink.
    If the analyzer complains about such a POTENTIAL FLAW inside a `Good*` method, it is considered FP, because it "fell for" a seemingly similar but safe path.

- `TP, FP, TN, FN` - True Positive, False Positive, True Negative, False Negative respectively

- `Bad path` - Juliet execution path that intentionally contains a vulnerable data flow

- `Good path` - Juliet execution path where the same sink may exist, but the data flow is safe.
- `Bad* method` - method treated as vulnerable region by the benchmark script.

- `Good* method` - method treated as safe region by the benchmark script.

- `Vulnerable point` - marked FLAW / POTENTIAL FLAW line inside a `Bad*` method.

- `Line window` - allowed distance in lines between a tool finding and a Juliet marker.

- `Unmatched FP / unmathed_fp` - finding inside a recognized Juliet region that does not match any expected FLAW/FIX point.

### Scan process

#### Benchmarking

The logic of metrics counting is the following:

1) Juliet has a set of methods in each file:

```csharp
Bad()
BadSink()
GoodG2B()
GoodB2G()
GoodG2BSink()
GoodB2GSink()
```

`Bad*` and `Good*` methods are considered bad and good regions respectively. The `Good()` dispatch method is not considered a separate region to avoid bloating the `TN`.

2) In each method we have types of comments or marked code lines:

```csharp
/* FLAW */
/* POTENTIAL FLAW */
/* FIX */
```

The benchmark script in `--no-cwe-aware` mode finds marked code lines, distinguish the marker and the determines how to count the finding:

* if finding near the marker FLAW/POTENTIAL FLAW in `Bad*` method -> TP. Even if several finding near the one vulnerable marked point, it is still only one TP, since the counting made according to marked points, not by tool's findings. *

* FLAW/POTENTIAL FLAW in `Bad*` without finding near the line aware region (5 by default in script) -> FN.

* FIX or safe-sink POTENTIAL FLAW in `Good*` method of -> FP. Several findings near one safe point also give one FP.

* If a finding hits a recognized Juliet `Bad*` or `Good*` method, but does not hit any FLAW/FIX points, it is considered a separate false positive -> unmached_fp. Final FP = unmached_fp + safe point with findings FP

* If safe pint does not have tool's finding nearby -> TN

Therefore, in `--no-cwe-aware` the script counts metrics only according to the tools' findings and not checks whether the tools made a correct finding.

The default mode of `benchmark_sarif.py` is `--cwe-aware`. In this mode, the line-aware matching described above is still used, but a finding is counted only if its CWE corresponds to the expected CWE of the Juliet testcase.

The script determines the CWE of a finding in the following order:

1) If `--rule-cwe-map` is provided, the script uses the explicit mapping from rule id to CWE:

```csv
rule_id,cwe
csharp.lang.security.sql-injection,CWE89
```

2) If the SARIF file contains rule metadata, the script reads CWE values from:

```text
runs[].tool.driver.rules[].properties.tags
```

This is required for tools such as CodeQL and PVS-Studio. CodeQL may store rule CWE values as tags such as `external/cwe/cwe-089`; PVS-Studio may store rule CWE values as tags such as `external/cwe/cwe-571`, while the individual result contains only a rule id such as `V3022`.

3) If the CWE is present directly in the rule id or in the finding message, the script uses it as a fallback.

CWE identifiers are normalized before comparison. For example, `CWE089`, `CWE-089` and `CWE89` are treated as the same CWE.

In `--cwe-aware` mode the classification rules are:

* A finding near FLAW or POTENTIAL FLAW in a `Bad*` method is counted as TP only if the finding CWE equals the testcase CWE.

* A finding near FIX or safe-sink POTENTIAL FLAW in a `Good*` method is counted as FP only if the finding CWE equals the testcase CWE.

* A finding inside a recognized Juliet region, but not near any FLAW/FIX point, is counted as `unmatched_fp` only if its CWE equals the testcase CWE.

* A finding with another CWE, or without a known CWE, is classified as `out_of_scope` and does not increase TP or FP for the current Juliet CWE.

For example, if a CodeQL finding `cs/web/cookie-secure-not-set` has CWE319 and appears near a Juliet CWE113 HTTP Response Splitting marker, it is classified as `out_of_scope`, not as TP or FP for CWE113.

This mode is used for strict comparison of tools when reliable CWE information is available. It is the recommended mode for CodeQL and PVS-Studio. For tools without reliable CWE mapping, such as the tested Semgrep/OpenGrep configuration, `--no-cwe-aware` can be used to evaluate only line-aware marker hits.


#### Semgrep

For testing Semgrep its Docker version were used:

```bash
docker run --rm -v "$PWD/src:/src" returntocorp/semgrep semgrep scan --sarif -o /src/semgrep.sarif --config auto /src
```

scanning all the testcases as a one project since Semgrep scanning allows this operation and it is more approximate to the real CI process in production.

After obtainig scanning result in `SARIF` format, the benchmark evaluating script were used [source](https://github.com/CompSAST/compsast-artifacts/blob/main/nist-csharp/benchmark_sarif.py):

```bash
python3 benchmark_sarif.py \
  --src src/testcases \
  --sarif sarif/semgrep.sarif \
  --tool semgrep \
  --out-dir results/semgrep_eval \
  --no-cwe-aware
``` 

#### Opengrep

Test suite was scanned by native Opengrep verion 1.20.0 with the following command:

```bash
cd ./src/testcases
opengrep scan --sarif -o ./opengrep.sarif ./
```

`SARIF` output after scan was measured similarly as the Semgrep's one:

```bash
python3 benchmark_sarif.py \
  --src src/testcases \
  --sarif sarif/opengrep.sarif \
  --tool opengrep \
  --out-dir results/opengrep_eval \
  --no-cwe-aware
```

##### Methodological limitation for Semgrep and OpenGrep

Semgrep and OpenGrep results were evaluated in `--no-cwe-aware` mode because the tested rule sets did not provide a reliable rule-to-CWE mapping.

Therefore, their metrics should be interpreted as line-aware marker matching results rather than strict CWE-aware vulnerability detection results. In this mode, a finding is counted if it appears near a Juliet FLAW, POTENTIAL FLAW, or FIX marker, but the benchmark does not verify whether the finding corresponds to the expected CWE of the testcase.

As a result, Semgrep and OpenGrep scores are not directly comparable with CodeQL and PVS-Studio scores evaluated in `--cwe-aware` mode. They should be treated as approximate results until a validated `rule_id -> CWE` mapping is provided and the benchmark is rerun in CWE-aware mode.

#### CodeQL

CodeQL and PVS-Studio for dotnet need project builds for analysis, therefore both of them were scanned on Windows 11 with Visual Studio installed.

CodeQL CLI version 2.25.2 was manually installed with the qlset from GitHub sources. The scanning scripts for per CWE-folder analysis below:

```powershell
codeql database create codeql-db-csharp ``
  --language=csharp ``
  --source-root . ``
  --command='powershell -NoProfile -ExecutionPolicy Bypass -File .\script.ps1'
```

script.ps1:

```powershell
msbuild .\src\testcasesupport\TestCaseSupport.sln /t:Restore,Rebuild /p:Configuration=Debug
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Get-ChildItem .\src\testcases -Recurse -Filter *.sln | ForEach-Object {
    msbuild $_.FullName /t:Restore,Rebuild /p:Configuration=Debug
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
```

analysis process:

```powershell
codeql database analyze .\codeql-db-csharp2 codeqlcsharp-security-extended.qls/csharp-queries:codeql-suites/csharp-security-extended.qls --format=sarif-latest --output=.\sarif\codeql.sarif --threads=4 --ram=8000
```

Getting the `SARIF` the following setup for CodeQL:

```bash
python3 benchmark_sarif.py \
    --src src/testcases \
    --sarif sarif/codeql-security.sarif \
    --tool codeql \
    --out-dir results/codeql_eval
```

#### PVS-Studio

PVS-Studio for dotnet v. 7.42.105479.2635 was installed, activated license and following scripts were used for per CWE-folder analysis:

```powershell
# analysis
$repo = "<path>\2020-08-01-juliet-test-suite-for-csharp-v1-3"
$pvs = "${env:ProgramFiles(x86)}\PVS-Studio\PVS-Studio_Cmd.exe"
$conv = "${env:ProgramFiles(x86)}\PVS-Studio\PlogConverter.exe"
$out = "$repo\_pvs"

New-Item -ItemType Directory -Force $out | Out-Null

Get-ChildItem "$repo\src\testcases" -Filter *.sln -Recurse | ForEach-Object {
    $sln = $_.FullName
    $id = $sln.Substring($repo.Length).TrimStart('\') -replace '[\\/:*?"<>| ]', '_'
    $plog = Join-Path $out "$id.plog"

    Write-Host "Analyzing $sln"
    & $pvs -t "$sln" -o "$plog"
}

# all-in one writting
$plogs = Get-ChildItem "$out" -Filter *.plog -Recurse |
  Where-Object { $_.Name -notmatch '^pvs-all\.' } |
  ForEach-Object { $_.FullName }

& $conv `
  -t Plog `
  -o "$out" `
  -r "$repo" `
  -m CWE,OWASP `
  -n "pvs-all" `
  @plogs

& $conv `
  -t Sarif,Csv `
  -o "$out" `
  -r "$repo" `
  -m CWE,OWASP `
  -n "pvs-all" `
  "$out\pvs-all.plog"
```

### Results

Summary for all SAST tools:

| tool | TP | FP | TN | FN | precision | recall | specificity | F1 | total vulnerable points | total safe points | total findings | unmatched FP findings | unknown findings | out-of-scope findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| CodeQL | 1,433 | 299 | 127,778 | 54,958 | 0.827367 | 0.025412 | 0.997665 | 0.049309 | 56,391 | 127,817 | 4,217 | 260 | 3 | 2,482 |
| OpenGrep | 671 | 4,673 | 126,961 | 55,720 | 0.125561 | 0.011899 | 0.964500 | 0.021738 | 56,391 | 127,817 | 5,344 | 3,817 | 0 | 0 |
| Semgrep | 671 | 4,673 | 126,961 | 55,720 | 0.125561 | 0.011899 | 0.964500 | 0.021738 | 56,391 | 127,817 | 5,344 | 3,817 | 0 | 0 |
| PVS-Studio | 1,324 | 217 | 127,710 | 55,067 | 0.859182 | 0.023479 | 0.998304 | 0.045709 | 56,391 | 127,817 | 54,437 | 110 | 6 | 52,870 |

Key observations:

- All tools show low recall on Juliet C# in the selected configuration: CodeQL 2.54%, PVS-Studio 2.35%, Semgrep/OpenGrep 1.19%.

- CodeQL and PVS-Studio have high precision after CWE-aware filtering: 82.74% and 85.92% respectively.

- As we can see Opengrep and Semgrep behave on this test suite absolutely the same. Even their precision measurement does not match measurements CodeQL and PVS-Studio, all metrics (precision, recall, specificity, f1) is noticeably lower.

- The `out-of-scope findings` column is especially important for CodeQL and PVS-Studio. These findings were reported by the tool, but their CWE did not match the expected CWE of the Juliet testcase. They were excluded from TP/FP counting in CWE-aware mode.

- PVS-Studio has 52,870 out-of-scope findings because the scan was performed with all available rules enabled. This means that the tool produced many diagnostics, but most of them were related to other CWE classes than the benchmark case currently being evaluated.

#### Juliet CWE coverage

| tool | CWE groups with TP | evaluated CWE groups |
| --- | ---: | ---: |
| CodeQL | 10 | 105 |
| PVS-Studio | 10 | 105 |
| Semgrep | 3 | 105 |
| OpenGrep | 3 | 105 |

More detailed statistics for each CWE availble at this [google sheet](https://docs.google.com/spreadsheets/d/1immwEj_XTfbIRZCNeEyJnkL1dWe9kQvq9gs83L8VNTI/edit?gid=705027058#gid=705027058)

All artifacts (benchmark scripts .csv outputs, .sarif scan outputs, script source code) can be found here: [repo](https://github.com/CompSAST/compsast-artifacts/tree/main/nist-csharp)

Overall, the results show that the tested tools are highly conservative on this benchmark configuration. CodeQL and PVS-Studio provide better precision, but their recall remains low because only a small subset of Juliet CWE classes is matched by the enabled rules and CWE-aware scoring. Semgrep and OpenGrep produce identical results and should be treated as line-aware marker matching baselines rather than strict CWE-aware SAST results.
