from dep_vuln_checker import __version__
from dep_vuln_checker.cli import build_parser, main


def test_version():
    assert __version__ == "0.1.0"


def test_parser_defaults():
    args = build_parser().parse_args([])
    assert args.path == "."


def test_main_returns_zero(capsys):
    rc = main(["."])
    assert rc == 0
    assert "dep-vuln-checker" in capsys.readouterr().out
