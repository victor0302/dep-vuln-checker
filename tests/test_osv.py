import io
import json
import time
from unittest.mock import patch

from dep_vuln_checker.osv import (
    BATCH_SIZE,
    Finding,
    Query,
    _cache_path,
    _cvss_to_severity,
    query,
)


def test_cache_key_is_stable_per_tuple(tmp_path):
    q = Query("PyPI", "requests", "2.31.0")
    assert _cache_path(q, tmp_path) == _cache_path(q, tmp_path)


def test_cache_key_differs_per_field(tmp_path):
    a = _cache_path(Query("PyPI", "requests", "2.31.0"), tmp_path)
    b = _cache_path(Query("PyPI", "requests", "2.31.1"), tmp_path)
    c = _cache_path(Query("PyPI", "django", "2.31.0"), tmp_path)
    d = _cache_path(Query("npm", "requests", "2.31.0"), tmp_path)
    assert {a, b, c, d} == {a, b, c, d}
    assert len({a, b, c, d}) == 4


def test_cvss_v3_high_to_critical():
    assert _cvss_to_severity({"severity": [{"score": "CVSS:3.1/9.8"}]}) == "critical"
    assert _cvss_to_severity({"severity": [{"score": "CVSS:3.1/7.5"}]}) == "high"
    assert _cvss_to_severity({"severity": [{"score": "CVSS:3.1/5.0"}]}) == "medium"
    assert _cvss_to_severity({"severity": [{"score": "CVSS:3.1/2.5"}]}) == "low"


def test_database_specific_fallback():
    assert _cvss_to_severity({"database_specific": {"severity": "MODERATE"}}) == "moderate"


def test_no_severity_is_unknown():
    assert _cvss_to_severity({}) == "unknown"


def _mock_urlopen(payload, status=200):
    body = json.dumps(payload).encode()
    response = io.BytesIO(body)
    response.__enter__ = lambda self: self
    response.__exit__ = lambda *a: None
    response.status = status
    return response


def test_batches_and_caches(tmp_path):
    vuln_stub = {
        "id": "GHSA-aaaa",
        "summary": "x",
        "severity": [{"score": "CVSS:3.1/9.8"}],
    }
    batch_resp = {"results": [{"vulns": [vuln_stub]}, {"vulns": []}]}
    with patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value = _mock_urlopen(batch_resp)
        findings = query(
            [Query("PyPI", "requests", "2.31.0"), Query("PyPI", "flask", "2.0.0")],
            cache_dir=tmp_path,
            fetch_full_details=False,
        )
    assert urlopen.call_count == 1  # single batched call
    assert len(findings) == 1
    assert findings[0].id == "GHSA-aaaa"
    assert findings[0].severity == "critical"

    # Second call: cache hit, no network.
    with patch("urllib.request.urlopen") as urlopen:
        findings2 = query(
            [Query("PyPI", "requests", "2.31.0"), Query("PyPI", "flask", "2.0.0")],
            cache_dir=tmp_path,
            fetch_full_details=False,
        )
    assert urlopen.call_count == 0
    assert findings2[0].id == "GHSA-aaaa"


def test_expired_cache_is_refetched(tmp_path):
    batch_resp = {"results": [{"vulns": []}]}
    with patch("urllib.request.urlopen") as urlopen:
        urlopen.return_value = _mock_urlopen(batch_resp)
        query([Query("PyPI", "x", "1.0.0")], cache_dir=tmp_path, fetch_full_details=False)
        urlopen.return_value = _mock_urlopen(batch_resp)
        query(
            [Query("PyPI", "x", "1.0.0")],
            cache_dir=tmp_path,
            fetch_full_details=False,
            ttl=0,
        )
    assert urlopen.call_count == 2


def test_chunks_into_max_batch_size(tmp_path):
    n = BATCH_SIZE + 5
    queries = [Query("PyPI", f"pkg{i}", "1.0.0") for i in range(n)]
    batch_resp = {"results": [{"vulns": []}] * BATCH_SIZE}
    extra_resp = {"results": [{"vulns": []}] * 5}

    calls: list[int] = []

    def fake_urlopen(req, timeout):
        body = json.loads(req.data)
        calls.append(len(body["queries"]))
        return _mock_urlopen(batch_resp if len(body["queries"]) == BATCH_SIZE else extra_resp)

    with patch("urllib.request.urlopen", side_effect=fake_urlopen):
        query(queries, cache_dir=tmp_path, fetch_full_details=False)
    assert calls == [BATCH_SIZE, 5]


def test_finding_shape():
    f = Finding(
        id="GHSA-x", package="requests", ecosystem="PyPI",
        version="2.31.0", severity="high", summary="boom",
        references=("https://example.com/advisory",),
    )
    assert f.id == "GHSA-x"
    assert isinstance(f.references, tuple)


def test_cache_freshness_keeps_under_ttl(tmp_path):
    cache_file = tmp_path / "x.json"
    cache_file.write_text(json.dumps([]))
    # touch it as recent
    now = time.time()
    import os
    os.utime(cache_file, (now, now))
