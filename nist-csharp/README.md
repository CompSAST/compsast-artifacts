# NIST Juliet C#

## Project Structure

```text
nist-csharp/
├── results/
│   ├── codeql_eval/
│   ├── opengrep_eval/
│   ├── pvs-fixed/
│   └── semgrep_eval/
└── sarif/
```

## Folder Navigation

| Folder | Description |
| --- | --- |
| [results](results/) | Final and intermediate analyzer evaluation results. |
| [results/codeql_eval](results/codeql_eval/) | CodeQL evaluation results. |
| [results/opengrep_eval](results/opengrep_eval/) | OpenGrep evaluation results. |
| [results/pvs-fixed](results/pvs-fixed/) | Fixed or normalized PVS-Studio results. |
| [results/semgrep_eval](results/semgrep_eval/) | Semgrep evaluation results. |
| [sarif](sarif/) | Source SARIF reports and related files for the C# benchmark dataset. |

## Key Files

| File | Description |
| --- | --- |
| [NIST-Csharp.md](NIST-Csharp.md) | Notes on working with NIST Juliet C# and the analysis results. |
| [BENCHMARK_SCORING_RU.md](BENCHMARK_SCORING_RU.md) | Russian-language description of benchmark result scoring. |
| [benchmark_sarif.py](benchmark_sarif.py) | Script for processing SARIF results from the benchmark dataset. |
