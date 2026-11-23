"""Tests for the CI/CD gate pieces: versions, SBOM, vulnerabilities (mocked OSV), secrets, policy and the gate itself."""
import datetime as dt
import json
import subprocess
from pathlib import Path

import pytest
import requests
from click.testing import CliRunner

from unslop import scanner, secretscan, vulns
from unslop.cli import main
from unslop.deps import Dep, added_deps, parse_deps
from unslop.gate import render_gate_markdown, run_gate, to_json
from unslop.policy import Policy, PolicyError, load_policy
from unslop.registry_client import PackageMetadata
from unslop.sarif import to_sarif
from unslop.sbom import build_sbom, purl

# Fake secrets are assembled at run time so this file itself never contains a scannable secret.
AWS = "AKIA" + "ABCDEFGH12345678"
GH = "ghp_" + "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"
PW = "Zq8#kL2mP9xW4vR7tY1"


# ---------------------------------------------------------------- versions
def test_requirements_pin_only_exact_versions():
    text = "requests==2.31.0\nflask>=2.0\ndjango[argon2]===4.2 ; python_version>'3.9'\nnumpy\n-r other.txt\n./local\n"
    got = {d.name: d.version for d in parse_deps("pypi", text, "requirements.txt")}
    assert got == {"requests": "2.31.0", "flask": None, "django": "4.2", "numpy": None}


def test_package_json_exact_vs_range_and_lock_versions():
    pj = json.dumps({"dependencies": {"a": "1.2.3", "b": "^1.2.3", "c": "~2.0.0", "d": "=3.0.0-beta.1"}})
    assert {d.name: d.version for d in parse_deps("npm", pj, "package.json")} == {"a": "1.2.3", "b": None, "c": None, "d": "3.0.0-beta.1"}
    lock = json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/lodash": {"version": "4.17.20"},
                                                           "node_modules/@s/p": {"version": "1.0.0"}, "node_modules/x": {"link": True}}})
    assert parse_deps("npm", lock, "package-lock.json") == [Dep("npm", "lodash", "4.17.20"), Dep("npm", "@s/p", "1.0.0")]


def test_pyproject_pep508_and_poetry_versions():
    text = '[project]\ndependencies = ["requests==2.0.0", "flask>=2"]\n[tool.poetry.dependencies]\npython = "^3.11"\nhttpx = "0.27.0"\nrich = "^13"\n'
    assert {d.name: d.version for d in parse_deps("pypi", text, "pyproject.toml")} == {"requests": "2.0.0", "flask": None, "httpx": "0.27.0", "rich": None}


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@t.t", "-c", "user.name=t", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path, monkeypatch):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "requirements.txt").write_text("requests==2.0.0\nflask==3.0.0\n")
    git(tmp_path, "add", "."); git(tmp_path, "commit", "-qm", "base")
    git(tmp_path, "checkout", "-qb", "pr")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_added_deps_counts_version_bumps_not_unchanged(repo):
    (repo / "requirements.txt").write_text("requests==2.1.0\nflask==3.0.0\nnumpy==1.26.0\n")
    git(repo, "commit", "-qam", "pr")
    assert {(d.name, d.version) for d in added_deps(Path("requirements.txt"), "main")} == {("requests", "2.1.0"), ("numpy", "1.26.0")}


# ---------------------------------------------------------------- SBOM
def test_purl_and_sbom_structure():
    assert purl(Dep("pypi", "Foo_Bar", "1.0")) == "pkg:pypi/foo-bar@1.0"
    assert purl(Dep("npm", "@scope/pkg", "2.0.0")) == "pkg:npm/%40scope/pkg@2.0.0"
    assert purl(Dep("npm", "left-pad")) == "pkg:npm/left-pad"
    doc = build_sbom({"a/requirements.txt": [Dep("pypi", "requests", "2.0.0"), Dep("pypi", "flask")],
                      "b/requirements.txt": [Dep("pypi", "requests", "2.0.0")]})
    assert doc["bomFormat"] == "CycloneDX" and doc["specVersion"] == "1.5" and doc["serialNumber"].startswith("urn:uuid:")
    comps = {c["purl"]: c for c in doc["components"]}
    assert set(comps) == {"pkg:pypi/requests@2.0.0", "pkg:pypi/flask"}
    assert len([p for p in comps["pkg:pypi/requests@2.0.0"]["properties"] if p["name"] == "unslop:manifest"]) == 2
    assert "version" not in comps["pkg:pypi/flask"]


# ---------------------------------------------------------------- vulnerabilities (OSV is mocked)
def test_cvss3_scores_match_the_spec_examples():
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5
    assert vulns.cvss3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert vulns.cvss3_score("CVSS:4.0/AV:N") is None and vulns.cvss3_score("garbage") is None


def test_severity_prefers_the_rating_then_the_vector():
    assert vulns.severity_of({"database_specific": {"severity": "MODERATE"}}) == ("medium", None)
    assert vulns.severity_of({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}) == ("critical", 9.8)
    assert vulns.severity_of({}) == ("unknown", None)


class FakeResp:
    def __init__(self, data): self.data = data
    def raise_for_status(self): pass
    def json(self): return self.data


class FakeOSV:
    def __init__(self, fail=False): self.calls, self.fail = [], fail
    def post(self, url, json=None, timeout=None):
        self.calls.append(("post", json))
        if self.fail: raise requests.ConnectionError("boom")
        return FakeResp({"results": [{"vulns": [{"id": "PYSEC-1"}]}, {}]})
    def get(self, url, timeout=None):
        vid = url.rsplit("/", 1)[1]
        recs = {"PYSEC-1": {"id": "PYSEC-1", "summary": "bad", "aliases": ["GHSA-aaaa"], "affected": [{"package": {"name": "requests"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}]},
                "GHSA-aaaa": {"id": "GHSA-aaaa", "database_specific": {"severity": "HIGH"}}}
        return FakeResp(recs[vid])


def test_osv_check_finds_severity_through_the_ghsa_alias_and_skips_unpinned():
    s = FakeOSV()
    found, errors = vulns.check([("r.txt", Dep("pypi", "requests", "2.0.0")), ("r.txt", Dep("pypi", "flask", "3.0.0")), ("r.txt", Dep("pypi", "numpy"))], session=s)
    assert errors == [] and len(found) == 1
    v = found[0]
    assert (v.package, v.version, v.id, v.severity, v.fixed_in, v.location) == ("requests", "2.0.0", "PYSEC-1", "high", ["2.20.0"], "r.txt")
    assert len(s.calls[0][1]["queries"]) == 2                       # the unpinned package was never sent


def test_osv_failure_is_reported_not_hidden():
    found, errors = vulns.check([("r.txt", Dep("pypi", "requests", "2.0.0"))], session=FakeOSV(fail=True))
    assert found == [] and errors == ["vulnerability lookup failed: ConnectionError"]


# ---------------------------------------------------------------- secrets
def diff_for(file, *added, start=1):
    body = "".join(f"+{line}\n" for line in added)
    return f"diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n@@ -0,0 +{start},{len(added)} @@\n{body}"


def test_known_token_formats_block_and_values_are_redacted():
    found = secretscan.scan_diff(diff_for("app.py", "x = 1", f'KEY = "{AWS}"', f"t = '{GH}'"))
    assert [(f.rule, f.line, f.severity) for f in found] == [("aws-access-key", 2, "block"), ("github-token", 3, "block")]
    assert all(AWS not in f.preview and GH not in f.preview for f in found)
    assert found[0].fingerprint == secretscan.scan_diff(diff_for("b.py", AWS))[0].fingerprint


def test_private_key_header_and_slack_token():
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert secretscan.scan_diff(diff_for("k.pem", header))[0].rule == "private-key"
    assert secretscan.scan_diff(diff_for("c.py", "s = '" + "xoxb-" + "1234567890-abcdefghij" + "'"))[0].rule == "slack-token"


def test_generic_credentials_only_warn_and_hide_every_character():
    f = secretscan.scan_diff(diff_for("c.py", f'password = "{PW}"'))
    assert [(x.rule, x.severity) for x in f] == [("generic-secret", "warn")] and PW[:4] not in f[0].preview
    for ok in ('password = "changeme-changeme-123"', 'api_key = "your-api-key-goes-here"', 'token = "${TOKEN_FROM_ENV_VAR}"', 'secret = "aaaaaaaaaaaaaaaaaaaa"'):
        assert secretscan.scan_diff(diff_for("c.py", ok)) == [], ok


def test_only_added_lines_skip_lists_and_allow_marker():
    removed = f"diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -1,1 +0,0 @@\n-KEY = '{AWS}'\n"
    assert secretscan.scan_diff(removed) == []
    assert secretscan.scan_diff(diff_for("package-lock.json", AWS)) == [] and secretscan.scan_diff(diff_for("node_modules/x/i.js", AWS)) == []
    assert secretscan.scan_diff(diff_for("a.py", f"K = '{AWS}'  # unslop:allow-secret")) == []


def test_line_numbers_follow_hunks():
    d = "diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n@@ -3,0 +4,1 @@\n+ok = 1\n@@ -9,0 +20,2 @@\n+a = 1\n" + f"+K = '{AWS}'\n"
    assert secretscan.scan_diff(d)[0].line == 21


# ---------------------------------------------------------------- policy
def test_policy_defaults_and_thresholds():
    p = Policy()
    assert p.vuln_blocks("critical") and p.vuln_blocks("high") and not p.vuln_blocks("medium") and not p.vuln_blocks("unknown")
    assert not Policy(block_on_vulnerability="none").vuln_blocks("critical") and Policy(block_on_vulnerability="low").vuln_blocks("low")


def test_policy_file_validation_and_waiver_expiry(tmp_path):
    f = tmp_path / "unslop.toml"
    f.write_text('[policy]\nblock_on_vulnerability = "critical"\n[[waiver]]\nid = "CVE-1"\nreason = "not reachable"\nexpires = 2026-12-31\n')
    p = load_policy(f)
    assert p.block_on_vulnerability == "critical"
    assert p.waiver_for(["CVE-1"], dt.date(2026, 11, 1))[0].reason == "not reachable"
    assert p.waiver_for(["CVE-1"], dt.date(2027, 1, 1)) == (None, True)
    for bad in ('[policy]\nunknown = 1\n', '[policy]\nblock_on_vulnerability = "severe"\n', '[[waiver]]\nid = "x"\n', '[policy]\nblock_on_secret = "yes"\n'):
        f.write_text(bad)
        with pytest.raises(PolicyError):
            load_policy(f)
    assert load_policy(tmp_path / "missing.toml").block_on_secret is True


# ---------------------------------------------------------------- the gate itself
@pytest.fixture
def risky_pr(repo, monkeypatch):
    monkeypatch.setattr(scanner, "fetch_metadata", lambda n, e: PackageMetadata(name=n, ecosystem=e, exists=False))
    monkeypatch.setattr(vulns, "check", lambda deps, **k: ([vulns.Vuln("PYSEC-1", "pypi", "requests", "2.1.0", "critical", 9.8, "bad", ["CVE-9"], ["2.20.0"], "requirements.txt")], []))
    (repo / "requirements.txt").write_text("requests==2.1.0\nflask==3.0.0\nreqeusts==1.0.0\n")
    (repo / "config.py").write_text(f'KEY = "{AWS}"\n')
    git(repo, "add", "."); git(repo, "commit", "-qm", "pr")
    return repo


def test_gate_blocks_on_all_three_and_never_leaks_the_secret(risky_pr):
    res = run_gate([Path("requirements.txt")], "main", Policy())
    kinds = " | ".join(res.blockers)
    assert "suspicious dependency `reqeusts`" in kinds and "critical vulnerability PYSEC-1" in kinds and "AWS access key ID at `config.py:1`" in kinds
    assert len(res.sbom["components"]) == 2 + 1                                           # requests, flask, reqeusts
    everything = render_gate_markdown(res) + json.dumps(to_json(res)) + json.dumps(to_sarif(res.reports, res.vulns, res.secrets))
    assert AWS not in everything
    levels = {r["ruleId"] for r in to_sarif(res.reports, res.vulns, res.secrets)["runs"][0]["results"]}
    assert levels == {"UNSLOP001", "UNSLOP002", "UNSLOP003"}


def test_waivers_policy_levels_and_expiry_change_the_decision(risky_pr):
    p = Policy(waivers=[])
    from unslop.policy import Waiver
    fp = run_gate([Path("requirements.txt")], "main", Policy()).secrets[0].fingerprint
    ok = Policy(block_on_vulnerability="none", waivers=[Waiver("pkg:pypi:reqeusts", "internal name"), Waiver(f"secret:{fp}", "test key")])
    res = run_gate([Path("requirements.txt")], "main", ok)
    assert res.blockers == [] and len(res.waived) == 2 and "Passed" in render_gate_markdown(res)
    expired = Policy(block_on_vulnerability="none", waivers=[Waiver("pkg:pypi:reqeusts", "old", dt.date(2020, 1, 1))])
    res = run_gate([Path("requirements.txt")], "main", expired, today=dt.date(2026, 11, 20))
    assert any("reqeusts" in b for b in res.blockers) and any("waiver has expired" in w for w in res.waived)


def test_gate_cli_exit_codes_and_outputs(risky_pr):
    out = risky_pr / "out"
    out.mkdir()
    r = CliRunner().invoke(main, ["gate", "requirements.txt", "--base", "main", "--no-cache", "--markdown", str(out / "c.md"), "--json", str(out / "r.json"),
                                  "--sarif", str(out / "r.sarif"), "--sbom", str(out / "bom.json"), "--github-output", str(out / "gh")])
    assert r.exit_code == 1 and "Decision: BLOCKED" in r.output and AWS not in r.output
    assert json.loads((out / "bom.json").read_text())["bomFormat"] == "CycloneDX" and json.loads((out / "r.sarif").read_text())["version"] == "2.1.0"
    assert "blocked=true" in (out / "gh").read_text() and "scanned=1" in (out / "gh").read_text() and "findings=3" in (out / "gh").read_text()
    (risky_pr / "unslop.toml").write_text('[policy]\nblock_on_vulnerability = "none"\nblock_on_secret = false\nblock_on_slopsquat = false\n')
    assert CliRunner().invoke(main, ["gate", "requirements.txt", "--base", "main", "--no-cache"]).exit_code == 0
    (risky_pr / "unslop.toml").write_text("[policy]\nnonsense = 1\n")
    assert CliRunner().invoke(main, ["gate", "requirements.txt", "--base", "main"]).exit_code == 2


def test_sbom_command_writes_a_file(tmp_path):
    f = tmp_path / "requirements.txt"; f.write_text("requests==2.31.0\nflask\n")
    out = tmp_path / "bom.json"
    r = CliRunner().invoke(main, ["sbom", str(f), "-o", str(out)])
    assert r.exit_code == 0 and len(json.loads(out.read_text())["components"]) == 2
