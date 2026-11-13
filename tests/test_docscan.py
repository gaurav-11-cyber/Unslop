"""Offline tests for install-command extraction and doc scanning."""
import subprocess
from pathlib import Path

from unslop import scanner
from unslop.docscan import extract_installs, is_doc_file, scan_doc
from unslop.heuristics import HallucinationEngine
from unslop.registry_client import PackageMetadata

MD = Path("README.md")


def names(text, path=MD):
    return sorted((i.ecosystem, i.name) for i in extract_installs(text, path))


def test_fenced_and_inline_commands():
    text = "Setup:\n```bash\n$ pip install requests flask\nnpm i -g @scope/tool@1.2 lodash@4\n```\nOr run `pip3 install numpy`.\n"
    assert names(text) == [("npm", "@scope/tool"), ("npm", "lodash"),
                           ("pypi", "flask"), ("pypi", "numpy"), ("pypi", "requests")]


def test_prose_is_not_treated_as_a_command():
    assert names("Use npm install to set things up, then pip install the deps.\n") == []


def test_flags_paths_urls_and_placeholders_are_skipped():
    text = ("```\npip install -r requirements.txt\npip install -e .\npip install ./local\n"
            "pip install git+https://github.com/a/b.git\npip install <package>\n"
            "pip install pkg --index-url https://x.example/simple good-lib\n```\n")
    assert names(text) == [("pypi", "good-lib")]


def test_version_specs_extras_and_quotes():
    text = '```\npip install "requests>=2.0" flask[async]==3.0 \'django<5\'\n```\n'
    assert names(text) == [("pypi", "django"), ("pypi", "flask"), ("pypi", "requests")]


def test_chained_commands_and_redirects_and_comments():
    text = "```\npip install aaa && npm install bbb ; pip install ccc | tee log\npip install ddd > out.txt\npip install eee # optional\n```\n"
    assert names(text) == [("npm", "bbb"), ("pypi", "aaa"), ("pypi", "ccc"), ("pypi", "ddd"), ("pypi", "eee")]


def test_npx_first_positional_and_package_flag():
    assert names("```\nnpx -y create-react-app my-app\n```\n") == [("npm", "create-react-app")]
    assert names("```\nnpx -p @scope/cli mybin --flag\n```\n") == [("npm", "@scope/cli")]


def test_dockerfile_continuation_and_line_numbers():
    text = "FROM python:3.12\nRUN pip install --no-cache-dir \\\n    requests \\\n    flask\n# RUN pip install ignored\n"
    found = extract_installs(text, Path("Dockerfile"))
    assert sorted(i.name for i in found) == ["flask", "requests"] and {i.line for i in found} == {2}


def test_is_doc_file():
    for n in ("README.md", "CLAUDE.md", "setup.sh", "ci.yml", "Dockerfile", "app.Dockerfile", ".cursorrules"):
        assert is_doc_file(Path(n)), n
    for n in ("requirements.txt", "package.json", "main.py"):
        assert not is_doc_file(Path(n)), n


def _meta(exists=True, **kw):
    base = dict(exists=exists, age_days=4000, weekly_downloads=10**6, has_repository=True,
                maintainer_count=3, version_count=30)
    base.update(kw)
    return lambda n, e: PackageMetadata(name=n, ecosystem=e, **base)


def test_only_new_installs_are_scanned_in_diff_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "fetch_metadata", _meta())
    run = lambda *a: subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=t", *a],
                                    cwd=tmp_path, check=True, capture_output=True)
    run("init", "-q", "-b", "main")
    doc = tmp_path / "README.md"
    doc.write_text("```\npip install requests\n```\n")
    run("add", "."); run("commit", "-qm", "base")
    doc.write_text("```\npip install requests numpy\nnpm install left-pad\n```\n")
    reports = scan_doc(doc, HallucinationEngine(), base_ref="main")
    got = {(r.ecosystem, a.package) for r in reports for a in r.passed + r.warned + r.blocked}
    assert got == {("pypi", "numpy"), ("npm", "left-pad")}
    assert any(a.location and a.location.endswith("README.md:2") for r in reports for a in r.passed + r.warned)


def test_unknown_package_in_docs_is_warn_but_incident_still_blocks(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "fetch_metadata", _meta(exists=False))
    doc = tmp_path / "SKILL.md"
    doc.write_text("```\npip install reqeusts\nnpm install react-codeshift\n```\n")
    eng = HallucinationEngine()
    rep = {r.ecosystem: r for r in scan_doc(doc, eng)}
    assert [a.package for a in rep["pypi"].warned] == ["reqeusts"] and not rep["pypi"].blocked
    assert [a.package for a in rep["npm"].blocked] == ["react-codeshift"]      # documented incident
    strict = {r.ecosystem: r for r in scan_doc(doc, eng, strict=True)}
    assert [a.package for a in strict["pypi"].blocked] == ["reqeusts"]
