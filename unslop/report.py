"""
report.py

Renders scan results as Markdown for a GitHub PR comment / job summary.

Package names come from the PR author, so they are untrusted: they are cut down
to characters that are legal in PyPI/npm names before being printed. This stops
markdown, HTML, @-mention and terminal-escape tricks.
"""

from __future__ import annotations

import re

from .scanner import ScanReport

# Hidden marker so the CI job can find and update its own earlier comment.
COMMENT_MARKER = "<!-- unslop-comment -->"

_ILLEGAL = re.compile(r"[^A-Za-z0-9@/._~+-]")
_ICON = {"block": "\u274c BLOCK", "warn": "\u26a0\ufe0f WARN", "pass": "\u2705 PASS"}


def safe_name(name: str, limit: int = 80) -> str:
    return _ILLEGAL.sub("?", name)[:limit]


def _cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(reports: list[ScanReport]) -> str:
    blocked = sum(len(r.blocked) for r in reports)
    warned = sum(len(r.warned) for r in reports)
    passed = sum(len(r.passed) for r in reports)
    checked = blocked + warned + passed

    lines = [COMMENT_MARKER, "## Unslop dependency check", ""]

    if checked == 0:
        lines.append("No new packages were added in this change, so nothing was scanned.")
        return "\n".join(lines) + "\n"

    if blocked:
        lines.append(f"**{blocked} blocked**, {warned} warned, {passed} passed "
                     f"({checked} new package(s) checked).")
    else:
        lines.append(f"No blocked packages. {warned} warned, {passed} passed "
                     f"({checked} new package(s) checked).")
    lines.append("")

    for rep in reports:
        flagged = rep.blocked + rep.warned
        if not flagged:
            continue
        lines += [f"### `{safe_name(rep.manifest, 200)}` ({rep.ecosystem})", "",
                  "| Package | Verdict | Risk | Why |", "|---|---|---|---|"]
        for a in flagged:
            why = " ".join(_cell(r) for r in a.reasons)
            lines.append(f"| `{safe_name(a.package)}` | {_ICON[a.verdict]} | {a.risk_score}/100 | {why} |")
        lines.append("")

    clean = [safe_name(a.package) for r in reports for a in r.passed]
    if clean:
        lines.append("Passed: " + ", ".join(f"`{n}`" for n in clean))
        lines.append("")

    lines.append("_Unslop checks new dependencies for AI-hallucinated (slopsquatted) names. "
                 "A warning is a signal to verify the package, not proof of malware._")
    return "\n".join(lines) + "\n"
