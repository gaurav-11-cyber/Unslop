"""Offline tests: nothing here talks to PyPI/npm (registry calls are faked)."""

import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from unslop import scanner
from unslop.cli import main
from unslop.gitdiff import GitError, added_packages
from unslop.registry_client import PackageMetadata
from unslop.report import COMMENT_MARKER, render_markdown, safe_name
from unslop.scanner import (
    VALID_NAME,
    ScanReport,
    parse_package_json_text,
    parse_requirements_text,
    scan_manifest,
)


# ------------------------------------------------------------------ parsing

def test_requirements_parsing_strips_versions_extras_markers_and_comments():
    text = "\n".join([
        "# a comment",
        "requests==2.31.0",
        "flask>=3.0  # inline comment",
        "pkg[extra]>=1.0; python_version < '3.9'",
        "-r other.txt",
        "git+https://github.com/x/y.git",
        "",
    ])
    assert parse_requirements_text(text) == ["requests", "flask", "pkg"]


def test_package_json_parsing_reads_deps_and_devdeps():
    text = '{"dependencies": {"react": "^18"}, "devDependencies": {"jest": "^29"}}'
    assert parse_package_json_text(text) == ["react", "jest"]


def test_package_json_invalid_raises_valueerror():
    with pytest.raises(ValueError):
        parse_package_json_text("{not json")


@pytest.mark.parametrize("name,ok", [
    ("requests", True), ("@types/node", True), ("a.b_c-d", True),
    ("@x", False), ("../etc", False), ("a b", False), ("x/y", False),
])
def test_valid_name(name, ok):
    assert bool(VALID_NAME.match(name)) is ok


# ---------------------------------------------------------------- git diff

def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    _git(tmp_path, "config", "user.email", "t@example.com")
    _git(tmp_path, "config", "user.name", "t")
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\nFlask_SQLAlchemy==3.0\n")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "base")
    _git(tmp_path, "checkout", "-q", "-b", "feature")
    return tmp_path


def test_added_packages_ignores_version_bumps_and_name_spelling(repo):
    (repo / "requirements.txt").write_text(
        "requests==2.32.0\nflask-sqlalchemy==3.1\nnewpkg==1.0\n")
    assert added_packages(repo / "requirements.txt", "main") == ["newpkg"]


def test_added_packages_new_file_means_everything_is_new(repo):
    (repo / "requirements-dev.txt").write_text("pytest\nblack\n")
    assert added_packages(repo / "requirements-dev.txt", "main") == ["pytest", "black"]


def test_added_packages_bad_ref_raises(repo):
    with pytest.raises(GitError):
        added_packages(repo / "requirements.txt", "origin/does-not-exist")


# ------------------------------------------------------------------ report

def test_safe_name_removes_markdown_and_control_characters():
    assert safe_name("evil`name|x\x1b[31m") == "evil?name?x??31m"


def test_markdown_has_marker_and_escapes(repo):
    from unslop.heuristics import RiskAssessment
    bad = RiskAssessment("evil`x", "pypi", 90, "block", ["bad | reason"])
    md = render_markdown([ScanReport("req.txt", "pypi", 1, blocked=[bad])])
    assert md.startswith(COMMENT_MARKER)
    assert "evil?x" in md and "`evil`x`" not in md
    assert "bad \\| reason" in md


def test_markdown_when_nothing_scanned():
    md = render_markdown([ScanReport("req.txt", "pypi", 0)])
    assert "nothing was scanned" in md


# --------------------------------------------------------------------- CLI

def _fake_registry(monkeypatch, exists_map):
    def fake_fetch(name, ecosystem, session=None):
        if exists_map.get(name, True):
            return PackageMetadata(name=name, ecosystem=ecosystem, exists=True, age_days=4000,
                                   weekly_downloads=10**6, has_repository=True,
                                   maintainer_count=3, version_count=50)
        return PackageMetadata(name=name, ecosystem=ecosystem, exists=False)
    monkeypatch.setattr(scanner, "fetch_metadata", fake_fetch)


def test_cli_blocks_known_hallucination_with_exit_1(repo, monkeypatch):
    _fake_registry(monkeypatch, {"cool-utils": False})
    (repo / "requirements.txt").write_text("requests==2.31.0\nFlask_SQLAlchemy==3.0\ncool-utils==1.0\n")
    result = CliRunner().invoke(main, ["scan", str(repo / "requirements.txt"), "--base", "main"])
    assert result.exit_code == 1
    assert "BLOCK  cool-utils" in result.output
    assert "packages checked: 1" in result.output


def test_cli_passes_with_exit_0_when_nothing_new(repo, monkeypatch):
    _fake_registry(monkeypatch, {})
    result = CliRunner().invoke(main, ["scan", str(repo / "requirements.txt"), "--base", "main"])
    assert result.exit_code == 0
    assert "No packages to scan" in result.output


def test_cli_bad_ref_exits_2(repo):
    result = CliRunner().invoke(main, ["scan", str(repo / "requirements.txt"), "--base", "nope"])
    assert result.exit_code == 2


def test_scan_manifest_flags_invalid_name_without_network(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("registry must not be called for invalid names")
    monkeypatch.setattr(scanner, "fetch_metadata", boom)
    f = tmp_path / "requirements.txt"
    f.write_text("../../etc/passwd\nfoo/../bar\n")      # first is a local path (ignored), second is an invalid name
    report = scan_manifest(f)
    assert [a.package for a in report.warned] == ["foo/../bar"] and report.total_packages == 1
