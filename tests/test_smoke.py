import json

import pytest

from dep_vuln_checker import __version__
from dep_vuln_checker.cli import build_parser, main
from dep_vuln_checker.lockfiles import detect_lockfiles
from dep_vuln_checker.severity import Severity


def test_version():
    assert __version__ == "0.1.0"


def test_parser_requires_subcommand():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_parser_check_defaults():
    args = build_parser().parse_args(["check", "."])
    assert args.command == "check"
    assert args.output == "text"
    assert args.min_severity == "low"


def test_main_no_lockfile_exits_zero(tmp_path, capsys):
    rc = main(["check", str(tmp_path)])
    assert rc == 0
    assert "No recognized lockfile" in capsys.readouterr().out


def test_main_with_lockfile_no_findings(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\n")
    rc = main(["check", str(tmp_path), "--output", "json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"findings": []}


def test_main_sarif_output(tmp_path, capsys):
    (tmp_path / "package-lock.json").write_text("{}")
    rc = main(["check", str(tmp_path), "--output", "sarif"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["tool"]["driver"]["name"] == "dep-vuln-checker"


def test_main_not_a_directory(tmp_path, capsys):
    f = tmp_path / "nope"
    f.write_text("")
    rc = main(["check", str(f)])
    assert rc == 2


def test_detect_lockfiles(tmp_path):
    (tmp_path / "requirements.txt").write_text("")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "package-lock.json").write_text("{}")
    found = [p.name for p in detect_lockfiles(tmp_path)]
    assert "requirements.txt" in found
    assert "package-lock.json" in found


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.NONE
