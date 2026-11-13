"""Offline tests for edge cases: registry failures, popular-package handling, scan robustness."""
from pathlib import Path

from unslop import scanner
from unslop.heuristics import HallucinationEngine
from unslop.registry_client import PackageMetadata


def test_network_error_is_unverified_not_hallucinated():
    meta = PackageMetadata(name="somepkg", ecosystem="pypi", exists=False, raw_error="timeout")
    a = HallucinationEngine().assess("somepkg", meta)
    text = " ".join(a.reasons)
    assert "Could not verify" in text and "does not exist" not in text
    assert a.verdict == "warn"          # visible, but never a hard block by itself


def test_genuinely_missing_package_is_still_flagged():
    meta = PackageMetadata(name="zzz-not-real-pkg", ecosystem="pypi", exists=False)
    assert "does not exist" in " ".join(HallucinationEngine().assess("zzz-not-real-pkg", meta).reasons)


def test_popular_package_is_never_a_typosquat_of_another_popular_package():
    eng = HallucinationEngine()
    meta = PackageMetadata(name="requests-oauthlib", ecosystem="pypi", exists=True,
                           age_days=3000, weekly_downloads=10**6, has_repository=True,
                           maintainer_count=3, version_count=40)
    a = eng.assess("requests-oauthlib", meta)
    assert a.verdict == "pass", a.reasons


def test_known_conflation_still_caught_with_large_popular_list():
    meta = PackageMetadata(name="react-codeshift", ecosystem="npm", exists=True,
                           age_days=300, weekly_downloads=4, has_repository=False,
                           maintainer_count=1, version_count=1)
    assert HallucinationEngine().assess("react-codeshift", meta).verdict == "block"


def test_scan_keeps_order_and_handles_duplicates_and_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "fetch_metadata",
                        lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=True, age_days=4000,
                                                     weekly_downloads=10**6, has_repository=True,
                                                     maintainer_count=3, version_count=30))
    f = tmp_path / "requirements.txt"
    f.write_text("requests\nflask\nrequests\n")
    r = scanner.scan_manifest(f)
    assert [a.package for a in r.passed] == ["requests", "flask", "requests"]
    empty = tmp_path / "requirements-empty.txt"
    empty.write_text("# nothing here\n\n")
    assert scanner.scan_manifest(empty).total_packages == 0
