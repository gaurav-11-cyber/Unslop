"""End-to-end CLI feature and failure-mode checks against the REAL PyPI/npm registries (needs network).

Run after `pip install -e .`:  python scripts/e2e_cli.py
Exits non-zero if any case fails. Not part of pytest because it needs network access.
"""
import json, os, shutil, subprocess, sys, tempfile, time
from pathlib import Path

BIN = shutil.which("unslop") or sys.exit("unslop is not on PATH (pip install -e . first)")
ENV = {**os.environ, "UNSLOP_NO_CACHE": "1"}
results = []

def run(name, files=None, args=None, exit=None, has=(), lacks=(), env=None, setup=None, timeout=120, check=None):
    d = Path(tempfile.mkdtemp(prefix="ft_"))
    for fn, content in (files or {}).items():
        (d / fn).parent.mkdir(parents=True, exist_ok=True)
        (d / fn).write_bytes(content if isinstance(content, bytes) else content.encode())
    if setup: setup(d)
    t = time.time()
    p = subprocess.run([BIN, *(args or [])], cwd=d, capture_output=True, env={**ENV, **(env or {})}, timeout=timeout)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    problems = []
    if exit is not None and p.returncode != exit: problems.append(f"exit {p.returncode} != {exit}")
    problems += [f"missing {s!r}" for s in has if s not in out]
    problems += [f"unexpected {s!r}" for s in lacks if s in out]
    if "Traceback" in out: problems.append("TRACEBACK")
    if check:
        try: check(d, out)
        except Exception as e: problems.append(f"check: {e}")
    results.append((name, not problems, problems, out, round(time.time() - t, 1)))

def git(d, *a): subprocess.run(["git", "-c", "user.email=a@b.c", "-c", "user.name=t", *a], cwd=d, check=True, capture_output=True)

# ---- requirements.txt
run("A1 clean popular", {"requirements.txt": "requests\nflask==3.0\n"}, ["scan", "requirements.txt"], 0, ["0 blocked, 0 warned, 2 passed"])
run("A2 typosquat blocks", {"requirements.txt": "reqeusts\n"}, ["scan", "requirements.txt"], 1, ["BLOCK  reqeusts"])
run("A3 empty file", {"requirements.txt": ""}, ["scan", "requirements.txt"], 0, ["packages checked: 0"])
run("A4 comments/options/inline", {"requirements.txt": "# c\n\n-r other.txt\n--index-url https://x.example/simple\nrequests # inline\n"}, ["scan", "requirements.txt"], 0, ["packages checked: 1"])
run("A5 CRLF", {"requirements.txt": "requests\r\nflask\r\n"}, ["scan", "requirements.txt"], 0, ["2 passed"])
run("A6 UTF-8 BOM", {"requirements.txt": b"\xef\xbb\xbfrequests\n"}, ["scan", "requirements.txt"], 0, ["1 passed"], ["nvalid"])
run("A7 non-UTF8 bytes", {"requirements.txt": b"requests\n\xff\xfe\n"}, ["scan", "requirements.txt"], None, [], ["Traceback"])
run("A8 URL/path lines", {"requirements.txt": "git+https://github.com/a/b.git\n./local\nrequests\n"}, ["scan", "requirements.txt"], 0, ["requests"], ["BLOCK"])
run("A9 duplicates/case", {"requirements.txt": "Requests\nrequests\nREQUESTS\n"}, ["scan", "requirements.txt"], 0)
def md_safe(d, o):
    md = (d / "c.md").read_text()
    assert "a|b" not in md and "evil.example" not in md and "<script" not in md, md
run("A10 markdown-injection names", {"requirements.txt": "a|b`c\nevil[x](http-evil.example)\n"}, ["scan", "requirements.txt", "--markdown", "c.md"], 0, check=md_safe)
run("A11 terminal escape in name", {"requirements.txt": "requests\x1b[31m\n"}, ["scan", "requirements.txt"], None, [], ["\x1b"])
run("A12 extras+markers", {"requirements.txt": "requests[security]>=2.0; python_version<'3.12'\n"}, ["scan", "requirements.txt"], 0, ["1 passed"])
run("A13 300-char name", {"requirements.txt": "a" * 300 + "\n"}, ["scan", "requirements.txt"], None, [], ["Traceback"])
# ---- package.json
run("B14 deps/dev/optional/scoped", {"package.json": json.dumps({"dependencies": {"react": "1"}, "devDependencies": {"@types/node": "1"}, "optionalDependencies": {"fsevents": "2"}})}, ["scan", "package.json"], 0, ["packages checked: 3"])
run("B15 invalid JSON", {"package.json": "{not json"}, ["scan", "package.json"], 2, ["nvalid"])
run("B16 JSON array root", {"package.json": "[]"}, ["scan", "package.json"], 2)
run("B17 empty object", {"package.json": "{}"}, ["scan", "package.json"], 0, ["packages checked: 0"])
run("B18 known incident", {"package.json": json.dumps({"dependencies": {"react-codeshift": "1"}})}, ["scan", "package.json"], 1, ["BLOCK  react-codeshift"])
# ---- lockfile / pyproject
run("C19 lock v3 incident", {"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {"": {}, "node_modules/react-codeshift": {}, "node_modules/lodash": {}}})}, ["scan", "package-lock.json"], 1, ["BLOCK  react-codeshift"])
run("C20 pyproject typosquat", {"pyproject.toml": '[project]\ndependencies = ["reqeusts"]\n'}, ["scan", "pyproject.toml"], 1, ["BLOCK  reqeusts"])
run("C21 invalid TOML", {"pyproject.toml": "[project\n"}, ["scan", "pyproject.toml"], 2, ["nvalid"])
# ---- docs
run("D22 skill file incident", {"SKILL.md": "```bash\nnpm install react-codeshift\n```\n"}, ["scan", "SKILL.md"], 1, ["BLOCK  react-codeshift", "SKILL.md:2"])
run("D23 prose not a command", {"README.md": "Use npm install to get started, then pip install the rest.\n"}, ["scan", "README.md"], 0, ["no install commands found"])
run("D24 Dockerfile continuation", {"Dockerfile": "FROM python:3.12\nRUN pip install requests \\\n    flask\n"}, ["scan", "Dockerfile"], 0, ["2 passed"])
run("D25 unknown in yml = WARN", {"ci.yml": "steps:\n  - run: pip install zzz-fake-pkg-qwerty\n"}, ["scan", "ci.yml"], 0, ["WARN  zzz-fake-pkg-qwerty"])
run("D26 --strict-docs = BLOCK", {"ci.yml": "steps:\n  - run: pip install reqeusts\n"}, ["scan", "ci.yml", "--strict-docs"], 1, ["BLOCK  reqeusts"])
# ---- options
run("E27 --only filter", {"requirements.txt": "requests\nreqeusts\n"}, ["scan", "requirements.txt", "--only", "requests"], 0, ["packages checked: 1"])
run("E28 --no-fail-on-block", {"requirements.txt": "reqeusts\n"}, ["scan", "requirements.txt", "--no-fail-on-block"], 0, ["BLOCK"])
def outputs(d, o):
    json.loads((d / "r.json").read_text()); s = json.loads((d / "r.sarif").read_text()); assert s["version"] == "2.1.0"; assert "Unslop" in (d / "c.md").read_text()
run("E29 json+markdown+sarif", {"requirements.txt": "reqeusts\n"}, ["scan", "requirements.txt", "--json", "r.json", "--markdown", "c.md", "--sarif", "r.sarif"], 1, check=outputs)
def mk(d):
    git(d, "init", "-q", "-b", "main"); git(d, "add", "."); git(d, "commit", "-qm", "b")
    (d / "requirements.txt").write_text("requests\nreqeusts\n"); git(d, "commit", "-qam", "p")
run("E30 --base valid", {"requirements.txt": "requests\n"}, ["scan", "requirements.txt", "--base", "HEAD~1"], 1, ["packages checked: 1", "BLOCK  reqeusts"], setup=mk)
run("E31 --base bad ref", {"requirements.txt": "requests\n"}, ["scan", "requirements.txt", "--base", "nope"], 2, setup=lambda d: (git(d, "init", "-q", "-b", "main"), git(d, "add", "."), git(d, "commit", "-qm", "b")))
run("E32 --base outside git", {"requirements.txt": "requests\n"}, ["scan", "requirements.txt", "--base", "main"], 2)
run("E33 missing path", {}, ["scan", "nope.txt"], 2)
run("E34 directory as path", {"d/x": "y"}, ["scan", "d"], 2)
run("E35 unsupported extension", {"foo.xml": "<a/>"}, ["scan", "foo.xml"], 2, ["nsupported"])
run("E36 one broken + one fine", {"package.json": "{bad", "requirements.txt": "requests\n"}, ["scan", "package.json", "requirements.txt"], 2, ["1 passed"])
run("E37 no args", {}, ["scan"], 2)
# ---- network & perf
run("F38 registry unreachable", {"requirements.txt": "some-obscure-pkg-xyzzy-q\n"}, ["scan", "requirements.txt"], 0, ["Could not verify"], ["does not exist"], env={"HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9", "UNSLOP_TIMEOUT": "2"}, timeout=90)
names = [n for n in (Path(__file__).resolve().parent.parent / "eval" / "data" / "legit_pypi.txt").read_text().split("\n") if n][:150]
run("F39 150 real packages (no cache)", {"requirements.txt": "\n".join(names) + "\n"}, ["scan", "requirements.txt"], None, ["packages checked: 150"], timeout=170)

bad = [r for r in results if not r[1]]
for n, ok, probs, out, secs in results: print(("PASS" if ok else "FAIL"), n, f"({secs}s)", "" if ok else probs)
print(f"\n{len(results) - len(bad)}/{len(results)} passed")
sys.exit(1 if bad else 0)
for n, ok, probs, out, secs in bad: print("\n=====", n, probs, "\n" + out[-700:])
