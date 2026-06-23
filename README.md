# dep-vuln-checker

Check project dependency manifests for known vulnerabilities.

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
dep-vuln-checker check <path-to-project> [--output text|json|sarif] [--min-severity ...] [--no-color]
```

## Develop

```bash
ruff check .
pytest
```

## Output formats

### Text

Findings grouped by `<ecosystem>/<package>@<version>`, sorted within each group by severity (critical first). ANSI colors by severity; disable with `--no-color`.

### JSON

```json
{
  "findings": [
    {
      "id": "GHSA-...",
      "package": "requests",
      "ecosystem": "PyPI",
      "version": "2.31.0",
      "severity": "high",
      "summary": "...",
      "references": ["https://example.com/advisory"]
    }
  ]
}
```

`severity` is one of `critical`, `high`, `medium`, `low`, `unknown`. Findings are sorted by `(ecosystem, package, id)` for deterministic output.

### SARIF

Emits SARIF 2.1.0. Each unique advisory becomes a rule in `runs[0].tool.driver.rules`; each finding becomes a result in `runs[0].results`. Severity → SARIF level: critical/high → `error`, medium → `warning`, low/unknown → `note`.
