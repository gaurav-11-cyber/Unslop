"""Regression tests for bugs found by the end-to-end feature run (scripts/e2e_cli.py)."""
import json
from pathlib import Path

from unslop import scanner
from unslop.docscan import extract_installs
from unslop.heuristics import HallucinationEngine
from unslop.report import render_markdown
from unslop.scanner import parse_names, parse_package_json_text, parse_requirements_text


def test_utf8_bom_is_ignored():
    assert parse_names("pypi", "\ufeffrequests\nflask\n", "requirements.txt") == ["requests", "flask"]
    assert parse_names("npm", '\ufeff{"dependencies":{"react":"1"}}', "package.json") == ["react"]
    assert [i.name for i in extract_installs("\ufeff```\npip install numpy\n```\n", Path("README.md"))] == ["numpy"]


def test_optional_and_peer_dependencies_are_scanned():
    text = json.dumps({"dependencies": {"a": "1"}, "devDependencies": {"b": "1"},
                       "optionalDependencies": {"c": "1"}, "peerDependencies": {"d": "1"}})
    assert parse_package_json_text(text) == ["a", "b", "c", "d"]


def test_local_paths_and_file_refs_are_not_package_names():
    assert parse_requirements_text("./local\n/abs/path\n~/x\nfile:///x\n-e .\nrequests\n") == ["requests"]


def test_markdown_report_neutralises_hostile_names(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: None)     # must never be called for invalid names
    f = tmp_path / "requirements.txt"
    f.write_text("a|b`c\nx\x1b[0m]\n")
    md = render_markdown([scanner.scan_manifest(f)])
    assert "\x1b" not in md and "a|b" not in md and "`c" not in md.replace("`a?b?c`", "")


def test_conflation_hint_wording_is_not_overclaiming(monkeypatch):
    from unslop.heuristics import HallucinationEngine
    from unslop.registry_client import PackageMetadata
    meta = PackageMetadata(name="react-codeshift", ecosystem="npm", exists=True, age_days=300, weekly_downloads=4,
                           has_repository=False, maintainer_count=1, version_count=1)
    text = " ".join(HallucinationEngine().assess("react-codeshift", meta).reasons)
    assert "weak signal" in text and "common AI hallucination pattern" not in text
