# NIST Juliet C#

## Структура проекта

```text
nist-csharp/
├── results/
│   ├── codeql_eval/
│   ├── opengrep_eval/
│   ├── pvs-fixed/
│   └── semgrep_eval/
└── sarif/
```

## Навигация по папкам

| Папка | Описание |
| --- | --- |
| [results](results/) | Итоговые и промежуточные результаты оценки анализаторов. |
| [results/codeql_eval](results/codeql_eval/) | Результаты оценки CodeQL. |
| [results/opengrep_eval](results/opengrep_eval/) | Результаты оценки OpenGrep. |
| [results/pvs-fixed](results/pvs-fixed/) | Исправленные или нормализованные результаты PVS-Studio. |
| [results/semgrep_eval](results/semgrep_eval/) | Результаты оценки Semgrep. |
| [sarif](sarif/) | Исходные SARIF-отчеты и связанные файлы для C# benchmark-набора. |

## Основные файлы

| Файл | Описание |
| --- | --- |
| [NIST-Csharp.md](NIST-Csharp.md) | Описание работы с NIST Juliet C# и результатами анализа. |
| [BENCHMARK_SCORING_RU.md](BENCHMARK_SCORING_RU.md) | Описание скоринга benchmark-результатов на русском языке. |
| [benchmark_sarif.py](benchmark_sarif.py) | Скрипт для обработки SARIF-результатов benchmark-набора. |
