"""secretscan.py - hard-coded secrets in the lines a pull request ADDS.

High-confidence patterns (well-known token formats) block by default; the generic "password = ..." rule only warns.
A secret is never printed in full: findings carry a short redacted preview and a fingerprint (for waivers).
Put `unslop:allow-secret` on a line to skip it. This is a small rule set, not a replacement for a full scanner.
"""
from __future__ import annotations

import hashlib
import math
import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

ALLOW_MARK = "unslop:allow-secret"
SKIP_NAMES = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock")
SKIP_SUFFIXES = (".lock", ".min.js", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".pdf", ".zip")
SKIP_DIRS = {"node_modules", "vendor", ".git"}

# id, human name, pattern (group 1 or the whole match is the secret), severity
RULES = [
    ("aws-access-key", "AWS access key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "block"),
    ("github-token", "GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,})\b"), "block"),
    ("private-key", "Private key block", re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----)"), "block"),
    ("slack-token", "Slack token", re.compile(r"\b(xox[abprs]-[A-Za-z0-9-]{10,})\b"), "block"),
    ("stripe-live-key", "Stripe live key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{24,})\b"), "block"),
    ("google-api-key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), "block"),
    ("npm-token", "npm access token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), "block"),
    ("pypi-token", "PyPI API token", re.compile(r"\b(pypi-AgE[A-Za-z0-9_-]{50,})\b"), "block"),
    ("ai-api-key", "AI provider API key", re.compile(r"\b(sk-(?:ant-|proj-)[A-Za-z0-9_-]{32,})\b"), "block"),
]
GENERIC = re.compile(r"""(?i)\b[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token)\b["']?\s*[:=]\s*["']([^"'\s]{16,})["']""")
PLACEHOLDER = re.compile(r"(?i)example|changeme|your[_-]|xxxx|<|>|\$\{|\{\{|dummy|sample|placeholder|redacted|insert|todo")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class SecretFinding:
    rule: str
    name: str
    file: str
    line: int
    severity: str          # "block" or "warn"
    fingerprint: str       # first 12 hex of sha256: stable id for waivers, reveals nothing
    preview: str           # redacted


def _entropy(s: str) -> float:
    return -sum(c / len(s) * math.log2(c / len(s)) for c in Counter(s).values())


def _preview(secret: str, rule: str) -> str:
    if secret.startswith("-----BEGIN"):
        return secret                                  # a header line, not the key itself
    return f"({len(secret)} chars)" if rule == "generic-secret" else f"{secret[:4]}... ({len(secret)} chars)"


def _skip(path: str) -> bool:
    p = Path(path)
    return p.name in SKIP_NAMES or path.lower().endswith(SKIP_SUFFIXES) or bool(SKIP_DIRS & set(p.parts))


def scan_line(line: str) -> list[tuple[str, str, str, str]]:
    """(rule id, name, secret, severity) for one line of text."""
    if ALLOW_MARK in line:
        return []
    found = [(rid, name, m.group(1), sev) for rid, name, rx, sev in RULES for m in rx.finditer(line)]
    if not found:
        for m in GENERIC.finditer(line):
            val = m.group(1)
            if not PLACEHOLDER.search(val) and _entropy(val) >= 3.5:
                found.append(("generic-secret", "Hard-coded credential", val, "warn"))
    return found


def scan_diff(diff: str) -> list[SecretFinding]:
    """Scan a `git diff -U0` text; only added lines are examined."""
    out: list[SecretFinding] = []
    file, line_no = "", 0
    for raw in diff.splitlines():
        if raw.startswith("+++ "):
            file = raw[4:].removeprefix("b/") if raw[4:] != "/dev/null" else ""
        elif (m := HUNK.match(raw)):
            line_no = int(m.group(1))
        elif raw.startswith("+") and not raw.startswith("+++"):
            if file and not _skip(file):
                for rid, name, secret, sev in scan_line(raw[1:]):
                    out.append(SecretFinding(rid, name, file, line_no, sev,
                                             hashlib.sha256(secret.encode()).hexdigest()[:12], _preview(secret, rid)))
            line_no += 1
    return out


def added_lines_diff(base_ref: str, cwd: Path = Path(".")) -> str:
    """Unified diff (no context) of what HEAD adds compared with the merge base of `base_ref`."""
    proc = subprocess.run(["git", "diff", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=AM", f"{base_ref}...HEAD", "--"],
                          cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        raise ValueError(f"could not diff against {base_ref}: {proc.stderr.strip()[:200]}")
    return proc.stdout
