"""Structure and behaviour of the reusable GitHub Action and the workflows (no GitHub needed)."""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parent.parent
FILES = [ROOT / "action.yml", *sorted((ROOT / ".github" / "workflows").glob("*.yml"))]


def steps_of(path):
    doc = yaml.safe_load(path.read_text())
    if "runs" in doc:
        return doc["runs"]["steps"]
    return [s for job in doc["jobs"].values() for s in job.get("steps", [])]


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_no_expression_injection_in_run_blocks(path):
    """`${{ ... }}` inside a shell `run:` is a script-injection risk: values must come in through env: instead."""
    for step in steps_of(path):
        assert "${{" not in step.get("run", ""), f"{path.name}: {step.get('name')}"


@pytest.mark.parametrize("path", FILES, ids=lambda p: p.name)
def test_third_party_actions_are_version_pinned(path):
    for step in steps_of(path):
        ref = step.get("uses")
        if ref and not ref.startswith("./"):
            assert re.search(r"@(v\d+|release/v\d+|[0-9a-f]{40})$", ref), ref


def test_action_is_a_composite_with_expected_inputs():
    doc = yaml.safe_load((ROOT / "action.yml").read_text())
    assert doc["runs"]["using"] == "composite"
    assert {"github-token", "comment", "fail-on-block", "strict-docs", "python-version"} <= set(doc["inputs"])
    for step in doc["runs"]["steps"]:
        if "run" in step:
            assert step.get("shell") == "bash"


# ---- run the action's real shell step against a temporary git repository -------------------------
needs_tools = pytest.mark.skipif(not (shutil.which("bash") and shutil.which("git")), reason="needs bash and git")


def scan_script():
    step = next(s for s in steps_of(ROOT / "action.yml") if s.get("id") == "scan")
    return step["run"]


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@t.t", "-c", "user.name=t", *args], cwd=cwd, check=True, capture_output=True)


def run_step(repo, tmp_path, base_ref="main", strict=""):
    out, summary = tmp_path / "gh_output", tmp_path / "gh_summary"
    out.write_text(""); summary.write_text("")
    env = {**os.environ, "BASE_REF": base_ref, "STRICT_DOCS": strict, "RUNNER_TEMP": str(tmp_path),
           "GITHUB_OUTPUT": str(out), "GITHUB_STEP_SUMMARY": str(summary),
           "UNSLOP_NO_CACHE": "1", "UNSLOP_TIMEOUT": "1",
           "PATH": str(Path(sys.executable).parent) + os.pathsep + os.environ["PATH"]}
    subprocess.run(["bash", "-c", scan_script()], cwd=repo, env=env, capture_output=True, timeout=120)
    return dict(line.split("=", 1) for line in out.read_text().splitlines() if "=" in line)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    (r / "requirements.txt").write_text("requests\n")
    git(r, "add", "."); git(r, "commit", "-qm", "base")
    git(r, "update-ref", "refs/remotes/origin/main", "HEAD")          # stand-in for the fetched base branch
    git(r, "checkout", "-qb", "pr")
    return r


@needs_tools
def test_step_blocks_a_documented_incident(repo, tmp_path):
    (repo / "package.json").write_text('{"dependencies": {"react-codeshift": "1.0.0"}}')
    git(repo, "add", "."); git(repo, "commit", "-qm", "pr")
    result = run_step(repo, tmp_path)
    assert result["exit_code"] == "1"
    assert "react-codeshift" in Path(result["comment_file"]).read_text()
    assert Path(result["sarif_file"]).exists()


@needs_tools
def test_step_ignores_prs_without_dependency_files(repo, tmp_path):
    (repo / "main.py").write_text("print(1)\n")
    git(repo, "add", "."); git(repo, "commit", "-qm", "pr")
    result = run_step(repo, tmp_path)
    assert result["exit_code"] == "0" and "comment_file" not in result


@needs_tools
def test_step_reports_setup_problems_as_exit_code_2(repo, tmp_path):
    assert run_step(repo, tmp_path, base_ref="")["exit_code"] == "2"            # not a pull_request event
    assert run_step(repo, tmp_path, base_ref="no-such-branch")["exit_code"] == "2"


def test_timeout_env_is_parsed_safely(monkeypatch):
    from unslop.registry_client import _timeout
    for raw, expected in (("abc", 8.0), ("0.1", 1.0), ("999", 60.0), ("3", 3.0)):
        monkeypatch.setenv("UNSLOP_TIMEOUT", raw)
        assert _timeout() == expected
    monkeypatch.delenv("UNSLOP_TIMEOUT")
    assert _timeout() == 8.0
