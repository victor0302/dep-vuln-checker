import textwrap

from dep_vuln_checker.parsers import requirements


def test_pinned_and_unpinned(tmp_path):
    f = tmp_path / "requirements.txt"
    f.write_text(textwrap.dedent("""\
        # comment line
        requests==2.31.0
        flask>=2.0  # web framework
        httpx
        django~=4.2
    """))
    deps = requirements.parse(f)
    assert deps == [
        ("requests", "2.31.0"),
        ("flask", "2.0"),
        ("httpx", None),
        ("django", "4.2"),
    ]


def test_extras_are_stripped(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text("uvicorn[standard]==0.27.0\n")
    assert requirements.parse(f) == [("uvicorn", "0.27.0")]


def test_recursive_includes(tmp_path):
    base = tmp_path / "base.txt"
    base.write_text("requests==2.31.0\n-r extra.txt\n")
    (tmp_path / "extra.txt").write_text("flask==3.0\n")
    deps = requirements.parse(base)
    assert ("requests", "2.31.0") in deps
    assert ("flask", "3.0") in deps


def test_recursive_includes_no_infinite_loop(tmp_path):
    a = tmp_path / "a.txt"
    b = tmp_path / "b.txt"
    a.write_text("-r b.txt\nrequests==2.31.0\n")
    b.write_text("-r a.txt\nflask==3.0\n")
    deps = requirements.parse(a)
    assert ("requests", "2.31.0") in deps
    assert ("flask", "3.0") in deps


def test_skips_url_installs(tmp_path, capsys):
    f = tmp_path / "r.txt"
    f.write_text(
        "requests==2.31.0\n"
        "git+https://github.com/x/y@main#egg=y\n"
        "-e git+https://github.com/x/z@main#egg=z\n"
        "https://example.com/pkg.tar.gz\n"
    )
    deps = requirements.parse(f)
    assert deps == [("requests", "2.31.0")]
    err = capsys.readouterr().err
    assert err.count("skipping unsupported install line") == 3


def test_ignores_other_flags(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text("--index-url https://pypi.org/simple\nrequests==2.31.0\n")
    assert requirements.parse(f) == [("requests", "2.31.0")]


def test_inequality_specifier_treated_as_unpinned(tmp_path):
    f = tmp_path / "r.txt"
    f.write_text("django!=4.0\n")
    assert requirements.parse(f) == [("django", "4.0")]
