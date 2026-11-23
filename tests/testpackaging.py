"""Release hygiene: things that break a release if they drift apart."""

import re
from pathlib import Path

import pytest

import inspector

ROOT = Path(__file__).resolve().parent.parent


def _names(specs):
    return {re.split(r"[<>=!~ ]", s.strip(), maxsplit=1)[0].lower() for s in specs if s.strip()}


def test_requirements_match_pyproject():
    tomllib = pytest.importorskip("tomllib")  # stdlib from Python 3.11; skipped on 3.10
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    lines = [x for x in (ROOT / "requirements.txt").read_text().splitlines() if x and not x.startswith("#")]
    assert _names(lines) == _names(pyproject["project"]["dependencies"])


def test_version_is_semver_and_in_changelog():
    assert re.fullmatch(r"\d+\.\d+\.\d+", inspector.__version__)
    assert f"## [{inspector.__version__}]" in (ROOT / "CHANGELOG.md").read_text()


def test_repository_files_exist():
    for name in ("LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", ".github/CODEOWNERS"):
        assert (ROOT / name).is_file(), name
