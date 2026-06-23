import json

from dep_vuln_checker.output import (
    Finding,
    render_json,
    render_sarif,
    render_text,
)


def _f(**kw):
    base = {
        "id": "GHSA-x",
        "package": "requests",
        "ecosystem": "PyPI",
        "version": "2.31.0",
        "severity": "high",
        "summary": "boom",
        "references": (),
    }
    base.update(kw)
    return Finding(**base)


def test_text_empty():
    assert render_text([]) == "No vulnerabilities found."


def test_text_groups_by_package_and_sorts_by_severity():
    findings = [
        _f(id="GHSA-a", package="x", severity="low"),
        _f(id="GHSA-b", package="x", severity="critical"),
        _f(id="GHSA-c", package="y", severity="medium"),
    ]
    out = render_text(findings, color=False)
    x_idx = out.index("PyPI/x")
    y_idx = out.index("PyPI/y")
    assert x_idx < y_idx
    # within x, critical before low
    crit_idx = out.index("GHSA-b")
    low_idx = out.index("GHSA-a")
    assert crit_idx < low_idx


def test_text_colors_when_enabled():
    out = render_text([_f(severity="critical")], color=True)
    assert "\x1b[" in out


def test_text_no_color():
    out = render_text([_f(severity="critical")], color=False)
    assert "\x1b[" not in out


def test_json_schema_stable():
    out = render_json([_f(references=("https://example.com",))])
    payload = json.loads(out)
    assert payload == {
        "findings": [
            {
                "id": "GHSA-x",
                "package": "requests",
                "ecosystem": "PyPI",
                "version": "2.31.0",
                "severity": "high",
                "summary": "boom",
                "references": ["https://example.com"],
            }
        ]
    }


def test_json_sorted_deterministically():
    a = _f(id="GHSA-a", package="zzz")
    b = _f(id="GHSA-b", package="aaa")
    out = render_json([a, b])
    payload = json.loads(out)
    assert [f["package"] for f in payload["findings"]] == ["aaa", "zzz"]


def test_sarif_structure():
    out = render_sarif([_f(severity="critical", references=("https://x",))])
    payload = json.loads(out)
    assert payload["version"] == "2.1.0"
    run = payload["runs"][0]
    assert run["tool"]["driver"]["name"] == "dep-vuln-checker"
    rules = run["tool"]["driver"]["rules"]
    assert rules[0]["id"] == "GHSA-x"
    assert rules[0]["helpUri"] == "https://x"
    assert run["results"][0]["ruleId"] == "GHSA-x"
    assert run["results"][0]["level"] == "error"


def test_sarif_levels_per_severity():
    levels = {}
    for sev in ("critical", "high", "medium", "low", "unknown"):
        payload = json.loads(render_sarif([_f(severity=sev)]))
        levels[sev] = payload["runs"][0]["results"][0]["level"]
    assert levels == {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "unknown": "note",
    }
