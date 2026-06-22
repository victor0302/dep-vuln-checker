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

## 2026-06-20 — Issues #3 / #4 / #5: parsers (requirements.txt, pyproject.toml, package-lock.json)

Landed the three lockfile parsers as standalone, unit-tested modules under `src/dep_vuln_checker/parsers/`. None of them are wired into the CLI yet — that's deferred to #6 (OSV client), when there's actually something to look the parsed deps up against.

- **requirements.txt** — handles `==`, `>=`, `~=`, `!=`, `<=`, `>`, `<`; strips `# comments` and `[extras]`; follows `-r other.txt` with cycle protection via a `seen` set; skips git+/url installs and `-e` editables with a stderr warning; ignores other CLI-style flags (`--index-url`, etc.).
- **pyproject.toml** — `tomllib` on 3.11+, `tomli` fallback on 3.10 (added as a conditional dep); reads `[project.dependencies]` plus every group in `[project.optional-dependencies]`; strips extras and environment markers.
- **package-lock.json** — walks the v2/v3 `packages` map; captures transitive deps via nested `node_modules/...` paths; handles scoped packages; rejects v1 with a clear `ValueError`; skips the empty-key root entry; de-dupes identical `(name, version)` across nesting levels.

All three return the same shape: `list[(name, version_or_None)]`, exposed as `parsers.Dep`.

Decisions:
- **Shared `Dep` type alias in `parsers/__init__.py`.** One module, one return type — keeps the OSV client honest when it consumes all three.
- **Three modules, not one switch.** Each parser has its own ugly edge cases (recursive `-r`, env markers, nested node_modules). A single mega-parser would be a soup. Dispatch by filename happens at the call site, not inside the parser.
- **No CLI wiring yet.** Parsers don't print anything; the CLI currently just emits empty findings. Wiring them in without an actual vulnerability source would just be a glorified `pip list` — pointless on its own. The wire-up lands with #6.
- **Conditional `tomli` dep instead of bumping min Python to 3.11.** Keeps the door open for users on 3.10 (still supported upstream); cost is one extra dep on old interpreters.
- **`-e` editable installs treated as URL installs.** They're almost always pointing at a VCS URL anyway; lumping them under the same warning keeps the parser simple.
- **`package-lock.json` v1 is a hard error, not a silent skip.** v1 stores the dep tree under `dependencies` instead of `packages` — silently returning `[]` would look like "no deps found", which is worse than telling the user we don't support it.
- **No PEP 440 version normalization.** The version string in the lockfile is what's actually installed; the OSV client gets to decide what "matches" means.

## Open follow-ups (tracked as issues)

- #6 OSV.dev client with batching + local cache
- #7 output formats: fill in real text / JSON / SARIF bodies
- #8 GitHub Actions: lint + test workflow
