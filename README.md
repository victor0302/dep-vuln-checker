# dep-vuln-checker

[![CI](https://github.com/victor0302/dep-vuln-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/victor0302/dep-vuln-checker/actions/workflows/ci.yml)

Check project dependency manifests for known vulnerabilities.

## Install

```bash
pip install -e ".[dev]"
```

## Run

```bash
dep-vuln-checker <path-to-project>
```

## Develop

```bash
ruff check .
pytest
```
