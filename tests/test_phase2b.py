"""Offline tests: lockfiles, pyproject.toml, popular-name shortcut, line locations, cache, SARIF, CLI."""
import json
import time
from pathlib import Path

from click.testing import CliRunner

from unslop import registry_client, scanner
from unslop.cli import main
from unslop.heuristics import HallucinationEngine
from unslop.registry_client import PackageMetadata
from unslop.sarif import to_sarif
from unslop.scanner import locate, parse_package_lock_text, parse_pyproject_text

GOOD = dict(exists=True, age_days=4000, weekly_downloads=10**6, has_repository=True, maintainer_count=3, version_count=30)


def test_package_lock_v3_and_v1():
    v3 = json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "app"}, "node_modules/lodash": {}, "node_modules/@scope/pkg": {},
        "node_modules/a/node_modules/b": {}, "packages/local": {}, "node_modules/linked": {"link": True}}})
    assert parse_package_lock_text(v3) == ["lodash", "@scope/pkg", "b"]
    v1 = json.dumps({"lockfileVersion": 1, "dependencies": {"x": {"version": "1", "dependencies": {"y": {}}}}})
    assert parse_package_lock_text(v1) == ["x", "y"]


def test_pyproject_pep621_groups_and_poetry():
    text = '''
[project]
dependencies = ["requests>=2.0", "flask[async]==3; python_version>'3.8'"]
[project.optional-dependencies]
dev = ["pytest"]
[dependency-groups]
lint = ["ruff>=0.1", {include-group = "dev"}]
[tool.poetry.dependencies]
python = "^3.11"
httpx = "^0.27"
[tool.poetry.group.test.dependencies]
hypothesis = "*"
'''
    assert parse_pyproject_text(text) == ["requests", "flask", "pytest", "ruff", "httpx", "hypothesis"]


def test_locate_finds_whole_token_line():
    text = "requests\nrequests-oauthlib\nevil-pkg==1\n"
    assert locate(text, "requests") == 1 and locate(text, "evil-pkg") == 3 and locate(text, "missing") == 1


def test_popular_packages_skip_registry_lookup(monkeypatch, tmp_path):
    calls = []
    def fake(n, e):
        calls.append(n)
        return PackageMetadata(name=n, ecosystem=e, **GOOD)
    monkeypatch.setattr(scanner, "fetch_metadata", fake)
    f = tmp_path / "requirements.txt"
    f.write_text("requests\nsome-obscure-pkg-xyz\n")
    rep = scanner.scan_manifest(f)
    assert calls == ["some-obscure-pkg-xyz"]                       # requests is top-5000: no lookup
    assert {a.package for a in rep.passed} == {"requests", "some-obscure-pkg-xyz"}


def test_known_incident_beats_the_popular_shortcut():
    eng = HallucinationEngine()
    assert eng._known_incident("react-codeshift", "npm") is not None and not eng.is_popular("react-codeshift", "npm")


def test_flagged_manifest_entries_get_a_line_location(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=False))
    f = tmp_path / "requirements.txt"
    f.write_text("# deps\nzzz-not-a-real-pkg==1.0\n")
    rep = scanner.scan_manifest(f)
    assert rep.warned[0].location.endswith("requirements.txt:2")


def test_cache_roundtrip_ttl_and_errors(monkeypatch, tmp_path):
    monkeypatch.delenv("UNSLOP_NO_CACHE")
    monkeypatch.setenv("UNSLOP_CACHE_DIR", str(tmp_path))
    calls = []
    def fake(n, e, session=None):
        calls.append(n)
        return PackageMetadata(name=n, ecosystem=e, **GOOD)
    monkeypatch.setattr(registry_client, "_fetch_uncached", fake)
    a = registry_client.fetch_metadata("pkg-a", "pypi")
    b = registry_client.fetch_metadata("pkg-a", "pypi")
    assert calls == ["pkg-a"] and b.exists and b.age_days == a.age_days            # second call served from cache
    for p in tmp_path.glob("*.json"):                                              # expire it
        blob = json.loads(p.read_text()); blob["stored_at"] = time.time() - 10**6; p.write_text(json.dumps(blob))
    registry_client.fetch_metadata("pkg-a", "pypi")
    assert calls == ["pkg-a", "pkg-a"]
    monkeypatch.setattr(registry_client, "_fetch_uncached",
                        lambda n, e, session=None: PackageMetadata(name=n, ecosystem=e, exists=False, raw_error="timeout"))
    registry_client.fetch_metadata("pkg-err", "pypi")
    assert len(list(tmp_path.glob("*.json"))) == 1                                  # errors are never cached


def test_sarif_structure_and_levels(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=False))
    f = tmp_path / "requirements.txt"
    f.write_text("reqeusts\nzzz-not-a-real-pkg\n")
    s = to_sarif([scanner.scan_manifest(f)])
    run = s["runs"][0]
    assert s["version"] == "2.1.0" and run["tool"]["driver"]["name"] == "Unslop"
    assert {r["level"] for r in run["results"]} == {"error", "warning"}
    loc = run["results"][0]["locations"][0]["physicalLocation"]
    assert loc["region"]["startLine"] >= 1 and loc["artifactLocation"]["uri"].endswith("requirements.txt")
    assert all(r["ruleId"] == run["tool"]["driver"]["rules"][0]["id"] for r in run["results"])


def test_cli_writes_sarif_and_json(monkeypatch, tmp_path):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=False))
    f = tmp_path / "requirements.txt"
    f.write_text("reqeusts\n")
    out = tmp_path / "o.sarif"
    r = CliRunner().invoke(main, ["scan", str(f), "--sarif", str(out), "--no-cache"])
    assert r.exit_code == 1 and json.loads(out.read_text())["runs"][0]["results"]
