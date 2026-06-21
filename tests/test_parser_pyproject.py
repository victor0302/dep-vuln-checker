import textwrap

from dep_vuln_checker.parsers import pyproject


def test_main_and_optional(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text(textwrap.dedent("""\
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = [
            "requests==2.31.0",
            "httpx>=0.27",
            "flask",
        ]

        [project.optional-dependencies]
        dev = ["pytest==8.0.0", "ruff>=0.5"]
        docs = ["sphinx~=7.2"]
    """))
    deps = pyproject.parse(f)
    assert ("requests", "2.31.0") in deps
    assert ("httpx", "0.27") in deps
    assert ("flask", None) in deps
    assert ("pytest", "8.0.0") in deps
    assert ("ruff", "0.5") in deps
    assert ("sphinx", "7.2") in deps


def test_extras_and_environment_markers_stripped(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text(textwrap.dedent("""\
        [project]
        name = "demo"
        version = "0.1.0"
        dependencies = [
            "uvicorn[standard]==0.27.0",
            "tomli>=2; python_version<'3.11'",
        ]
    """))
    deps = pyproject.parse(f)
    assert ("uvicorn", "0.27.0") in deps
    assert ("tomli", "2") in deps


def test_no_project_section(tmp_path):
    f = tmp_path / "pyproject.toml"
    f.write_text("[tool.ruff]\nline-length = 100\n")
    assert pyproject.parse(f) == []
