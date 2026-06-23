from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
BATCH_SIZE = 1000
CACHE_TTL_SECONDS = 24 * 60 * 60


@dataclass(frozen=True)
class Query:
    ecosystem: str
    name: str
    version: str | None


@dataclass(frozen=True)
class Finding:
    id: str
    package: str
    ecosystem: str
    version: str | None
    severity: str
    summary: str
    references: tuple[str, ...]


SEVERITY_BY_SCORE: tuple[tuple[float, str], ...] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
)


def _cache_dir() -> Path:
    base = os.environ.get("DEP_VULN_CACHE")
    if base:
        return Path(base)
    return Path.home() / ".cache" / "dep-vuln-checker"


def _cache_key(query: Query) -> str:
    raw = f"{query.ecosystem}|{query.name}|{query.version or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_path(query: Query, cache_dir: Path) -> Path:
    return cache_dir / f"{_cache_key(query)}.json"


def _load_cached(query: Query, cache_dir: Path, ttl: int) -> list[dict] | None:
    path = _cache_path(query, cache_dir)
    if not path.exists():
        return None
    age = time.time() - path.stat().st_mtime
    if age > ttl:
        return None
    return json.loads(path.read_text())


def _store_cached(query: Query, cache_dir: Path, vulns: list[dict]) -> None:
    cache_dir.mkdir(parents=True, exist_ok=True)
    _cache_path(query, cache_dir).write_text(json.dumps(vulns))


def _coerce_score(value: object) -> float | None:
    if isinstance(value, (int, float)):
        return float(value)
    if not isinstance(value, str):
        return None
    try:
        return float(value)
    except ValueError:
        pass
    # OSV often stores CVSS as a vector string; pull the last `/N.N` token.
    for token in reversed(value.split("/")):
        try:
            return float(token)
        except ValueError:
            continue
    return None


def _cvss_to_severity(vuln: dict) -> str:
    for entry in vuln.get("severity", []) or []:
        num = _coerce_score(entry.get("score"))
        if num is None:
            continue
        for threshold, label in SEVERITY_BY_SCORE:
            if num >= threshold:
                return label
    db_severity = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(db_severity, str):
        return db_severity.lower()
    return "unknown"


def _normalize(vuln: dict, query: Query) -> Finding:
    return Finding(
        id=vuln.get("id", "OSV-UNKNOWN"),
        package=query.name,
        ecosystem=query.ecosystem,
        version=query.version,
        severity=_cvss_to_severity(vuln),
        summary=vuln.get("summary") or vuln.get("details", "") or "",
        references=tuple(r.get("url", "") for r in vuln.get("references", []) if r.get("url")),
    )


def _post(url: str, payload: dict, timeout: float) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read())


def _get(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read())


def query(
    queries: Iterable[Query],
    *,
    cache_dir: Path | None = None,
    ttl: int = CACHE_TTL_SECONDS,
    timeout: float = 30.0,
    fetch_full_details: bool = True,
) -> list[Finding]:
    cache = cache_dir or _cache_dir()
    queries_list = list(queries)

    cached_results: dict[Query, list[dict]] = {}
    misses: list[Query] = []
    for q in queries_list:
        hit = _load_cached(q, cache, ttl)
        if hit is None:
            misses.append(q)
        else:
            cached_results[q] = hit

    for batch_start in range(0, len(misses), BATCH_SIZE):
        chunk = misses[batch_start : batch_start + BATCH_SIZE]
        payload = {
            "queries": [
                {
                    "package": {"name": q.name, "ecosystem": q.ecosystem},
                    **({"version": q.version} if q.version else {}),
                }
                for q in chunk
            ]
        }
        resp = _post(OSV_BATCH_URL, payload, timeout)
        results = resp.get("results", [])
        for q, result in zip(chunk, results, strict=False):
            vuln_stubs = result.get("vulns") or []
            cached_results[q] = vuln_stubs
            _store_cached(q, cache, vuln_stubs)

    findings: list[Finding] = []
    for q in queries_list:
        for stub in cached_results.get(q, []):
            full = stub
            vuln_id = stub.get("id")
            if fetch_full_details and vuln_id and not stub.get("summary"):
                try:
                    full = _get(OSV_VULN_URL.format(vuln_id=vuln_id), timeout)
                except OSError:
                    full = stub
            findings.append(_normalize(full, q))
    return findings
