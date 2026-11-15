"""
docscan.py

Finds package install commands inside documentation, scripts and CI files and
scans the package names they mention.

Why: slopsquatting does not only arrive through requirements.txt. AI agents and
developers copy `pip install ...` / `npm install ...` lines out of READMEs,
agent instruction files (CLAUDE.md, AGENTS.md, SKILL.md, .cursorrules), setup
scripts, Dockerfiles and CI YAML. The react-codeshift incident spread through
agent skill files, not manifests.

Commands are only PARSED (with shlex), never executed.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

from .gitdiff import _normalize as normalize_name
from .gitdiff import read_at_ref
from .heuristics import HallucinationEngine
from .scanner import ScanReport, VALID_NAME, scan_items

MD_SUFFIXES = {".md", ".mdx", ".markdown"}
MD_NAMES = {".cursorrules", ".windsurfrules", ".clinerules"}
RAW_SUFFIXES = {".sh", ".bash", ".yml", ".yaml"}
MAX_BYTES = 1_000_000

# (ecosystem, option family, command pattern)
_B = r"(?<![\w./-])"
_COMMANDS = [
    ("pypi", "pip", re.compile(_B + r"(?:python[0-9.]*\s+-m\s+)?pip[0-9.]*\s+install\b")),
    ("pypi", "pip", re.compile(_B + r"pipx\s+install\b")),
    ("pypi", "pip", re.compile(_B + r"uv\s+(?:pip\s+install|add)\b")),
    ("pypi", "pip", re.compile(_B + r"poetry\s+add\b")),
    ("npm", "npm", re.compile(_B + r"npm\s+(?:install|i|add)\b")),
    ("npm", "npm", re.compile(_B + r"(?:yarn|pnpm|bun)\s+add\b")),
    ("npm", "npx", re.compile(_B + r"npx\b")),
]

# Options that consume the NEXT token (so it is not mistaken for a package name).
_TAKES_VALUE = {
    "pip": {"-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url",
            "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
            "--python", "--platform", "--implementation", "--abi", "--python-version", "--src",
            "--cache-dir", "--proxy", "--trusted-host", "--with", "--group", "--extras"},
    "npm": {"--prefix", "--registry", "--tag", "-w", "--workspace", "--cache", "--userconfig"},
    "npx": {"-c", "--call", "--node-arg", "--registry", "--cache"},
}
_PLACEHOLDERS = {"package", "pkg", "package-name", "package_name", "your-package", "your_package",
                 "my-package", "my_package", "mypackage", "yourpackage", "module", "name", "..."}
_REDIRECTS = {">", ">>", "<", "2>", "2>&1", "&>", "1>"}
_ARCHIVE = (".whl", ".tar.gz", ".zip", ".tgz", ".tar")


@dataclass(frozen=True)
class Install:
    ecosystem: str
    name: str
    line: int


def is_doc_file(path: Path) -> bool:
    n = path.name.lower()
    return (path.suffix.lower() in MD_SUFFIXES | RAW_SUFFIXES or n in MD_NAMES
            or n == "dockerfile" or n.startswith("dockerfile.") or n.endswith(".dockerfile"))


def _is_markdown(path: Path) -> bool:
    return path.suffix.lower() in MD_SUFFIXES or path.name.lower() in MD_NAMES


def _code_lines(text: str, markdown: bool) -> Iterator[tuple[int, str]]:
    """Yield (line_number, code_text) for the parts of the file that can hold commands."""
    pending, pending_line, in_fence = "", 0, False
    for no, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if markdown:
            if stripped.startswith(("```", "~~~")):
                in_fence = not in_fence
                continue
            if not in_fence:                       # prose: only look inside `inline code`
                for span in re.findall(r"`+([^`\n]+)`+", raw):
                    yield no, span
                continue
        elif stripped.startswith("#"):             # commented-out line in a script/YAML
            continue
        if raw.rstrip().endswith("\\"):            # line continuation
            if not pending:
                pending_line = no
            pending += raw.rstrip()[:-1] + " "
            continue
        yield (pending_line, pending + raw) if pending else (no, raw)
        pending = ""
    if pending:
        yield pending_line, pending


def _cut(rest: str) -> str:
    """Cut a command at the first unquoted &&, ||, |, ;, backtick or ` #` comment."""
    quote = ""
    for i, ch in enumerate(rest):
        if quote:
            if ch == quote:
                quote = ""
        elif ch in "\"'":
            quote = ch
        elif ch in ";|`" or rest.startswith("&&", i) or (ch == "#" and i > 0 and rest[i - 1] == " "):
            return rest[:i]
    return rest


def _name_from(token: str, ecosystem: str) -> Optional[str]:
    if (not token or "://" in token or token.startswith(("git+", "github:", "file:", "link:", "npm:",
                                                         ".", "/", "~", "$", "<", "{"))
            or token.lower().endswith(_ARCHIVE)):
        return None
    if ecosystem == "pypi":
        name = re.split(r"[<>=!~\[;]", token, maxsplit=1)[0]
        if "/" in name or "@" in name:
            return None
    else:
        if token.startswith("@"):
            name = "@" + token[1:].split("@")[0]
            if name.count("/") != 1:
                return None
        else:
            name = token.split("@")[0]
            if "/" in name:                         # user/repo GitHub shorthand or a path
                return None
    if not VALID_NAME.match(name) or name.lower() in _PLACEHOLDERS:
        return None
    return name


def _parse_args(rest: str, ecosystem: str, family: str) -> list[str]:
    try:
        tokens = shlex.split(_cut(rest))
    except ValueError:
        tokens = _cut(rest).split()
    takes = _TAKES_VALUE[family]
    names: list[str] = []
    npx_p: list[str] = []
    skip = False
    for i, tok in enumerate(tokens):
        if tok in _REDIRECTS:
            break
        if skip:
            skip = False
            if family == "npx" and tokens[i - 1] in ("-p", "--package"):
                npx_p.append(tok)
            continue
        if tok in takes or (family == "npx" and tok in ("-p", "--package")):
            skip = True
            continue
        if tok.startswith("-"):
            continue
        if family == "npx":                         # first positional = package or local bin; the rest = its args
            n = _name_from(tok, "npm")
            if n and not npx_p:
                names.append(n)
            break
        n = _name_from(tok, ecosystem)
        if n:
            names.append(n)
    for p in npx_p:
        n = _name_from(p, "npm")
        if n:
            names.append(n)
    return names


def extract_installs(text: str, path: Path) -> list[Install]:
    text = text.removeprefix("\ufeff")
    found: dict[tuple[str, str, int], Install] = {}
    for line_no, code in _code_lines(text, _is_markdown(path)):
        for ecosystem, family, pattern in _COMMANDS:
            for m in pattern.finditer(code):
                for name in _parse_args(code[m.end():], ecosystem, family):
                    found.setdefault((ecosystem, name, line_no), Install(ecosystem, name, line_no))
    return list(found.values())


def scan_doc(
    path: Path,
    engine: HallucinationEngine,
    base_ref: Optional[str] = None,
    only: Optional[list[str]] = None,
    strict: bool = False,
) -> list[ScanReport]:
    """Scan install commands in one doc/script file. One report per ecosystem found."""
    if path.stat().st_size > MAX_BYTES:
        return []
    found = extract_installs(path.read_text(encoding="utf-8", errors="replace"), path)

    if base_ref:
        base_text = read_at_ref(path, base_ref)
        old = set()
        if base_text is not None:
            old = {(i.ecosystem, normalize_name(i.name, i.ecosystem)) for i in extract_installs(base_text, path)}
        found = [i for i in found if (i.ecosystem, normalize_name(i.name, i.ecosystem)) not in old]
    if only is not None:
        keep = {n.lower() for n in only}
        found = [i for i in found if i.name.lower() in keep]

    reports = []
    for ecosystem in ("pypi", "npm"):
        first: dict[str, str] = {}
        for i in found:
            if i.ecosystem == ecosystem:
                first.setdefault(i.name, f"{path}:{i.line}")
        if first:
            reports.append(scan_items(f"{path} (install commands)", ecosystem, list(first.items()),
                                      engine, docs=True, strict_docs=strict))
    return reports
