import json

import pytest

from dep_vuln_checker.parsers import package_lock


def _write_lockfile(path, payload):
    path.write_text(json.dumps(payload))


def test_v3_root_and_transitives(tmp_path):
    f = tmp_path / "package-lock.json"
    _write_lockfile(f, {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/express/node_modules/qs": {"version": "6.11.0"},
            "node_modules/@scope/pkg": {"version": "2.0.0"},
        },
    })
    deps = package_lock.parse(f)
    assert ("express", "4.18.2") in deps
    assert ("qs", "6.11.0") in deps
    assert ("@scope/pkg", "2.0.0") in deps
    assert ("demo", "1.0.0") not in deps


def test_v2_is_supported(tmp_path):
    f = tmp_path / "package-lock.json"
    _write_lockfile(f, {
        "lockfileVersion": 2,
        "packages": {
            "": {"name": "x", "version": "1.0.0"},
            "node_modules/lodash": {"version": "4.17.21"},
        },
    })
    assert ("lodash", "4.17.21") in package_lock.parse(f)


def test_v1_is_rejected(tmp_path):
    f = tmp_path / "package-lock.json"
    _write_lockfile(f, {"lockfileVersion": 1, "dependencies": {}})
    with pytest.raises(ValueError, match="unsupported lockfileVersion"):
        package_lock.parse(f)


def test_dedupes_repeats(tmp_path):
    f = tmp_path / "package-lock.json"
    _write_lockfile(f, {
        "lockfileVersion": 3,
        "packages": {
            "node_modules/a": {"version": "1.0.0"},
            "node_modules/x/node_modules/a": {"version": "1.0.0"},
        },
    })
    assert package_lock.parse(f) == [("a", "1.0.0")]
