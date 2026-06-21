# dep-vuln-checker — progress notes

Running log of what's been built and why. Append-only.

## 2026-06-17 — Issue #1: scaffolding

Laid down the project skeleton so the rest of the tickets have somewhere to land.

- `pyproject.toml` with PEP 621 metadata, a `dep-vuln-checker` console script entry point
- `src/` layout: `src/dep_vuln_checker/` package, version string, empty `cli.py`
- `tests/` with a passing smoke test that imports the package and exercises the CLI shell
- ruff + pytest pinned via the `[dev]` extra so a single `pip install -e ".[dev]"` is enough

Decisions:
- **`src/` layout over flat layout.** Forces tests to use the installed package, catches "works in-tree, breaks on install" bugs early.
- **setuptools, not hatch/poetry.** Stdlib-adjacent and lowest friction for a CLI with no exotic build needs.
- **ruff rules: `E, F, I, UP, B`.** Lint + import sort + modernizers + bugbear. No `D` (docstring rules) — comment overhead isn't worth it on a CLI this small.

## 2026-06-17 — Issue #2: `check` subcommand

Built out the top-level CLI surface. No real scanning yet — parsers and the OSV client come in #3–#6.

- `dep-vuln-checker check <path>` subcommand (other commands can slot in later)
- `--output {text,json,sarif}` — SARIF emits a minimal 2.1.0 envelope so CI tooling can consume it
- `--min-severity {none,low,medium,high,critical}` (default `low`) — the threshold for non-zero exit
- Lockfile auto-detection (`requirements.txt`, `pyproject.toml`, `package-lock.json`) via recursive glob
- Exit codes: `0` clean / no lockfile, `1` finding ≥ threshold, `2` bad input

Decisions:
- **Subcommand from day one.** Cheap to add now, expensive to retrofit. Leaves room for `list-lockfiles`, `update-db`, etc.
- **SARIF stub now, fill later.** Wiring the format string through the pipeline is the hard part; emitting an empty `runs` array is trivial.
- **Severity as an `IntEnum`.** Lets `>=` do the threshold comparison directly instead of a lookup table.
- **Exit `2` for bad input.** Reserves `1` for "found something" — the same convention `grep` and most CI-friendly scanners use.

## Open follow-ups (tracked as issues)

- #3 parser: `requirements.txt`
- #4 parser: `pyproject.toml` (PEP 621)
- #5 parser: `package-lock.json`
- #6 OSV.dev client with batching + local cache
- #7 output formats: fill in real text / JSON / SARIF bodies
- #8 GitHub Actions: lint + test workflow
