# Unslop

Catches **slopsquatted / AI-hallucinated package names** before they get installed.

## The problem

AI coding assistants hallucinate package names that don't exist (~20% of
AI-generated code samples, per a USENIX Security 2025 study). Attackers
register those exact names on PyPI/npm with malware inside — a documented
attack class called **slopsquatting**. Real incidents already exist:
`react-codeshift` (a hallucinated conflation of `jscodeshift` +
`react-codemod`) spread to 237 GitHub repos before a researcher defensively
registered it himself. CISA and the NSA issued a joint advisory on AI-agent
supply chain risk in early 2026. No mainstream SCA tool (Snyk, Dependabot,
SonarQube) targets this specific attack class yet.

## What it does

Scans `requirements.txt` / `package.json` for newly added dependencies and
scores each one for slopsquatting risk using four signals:

1. **Known-incident lookup** — matches against a corpus of documented
   hallucinated/slopsquatted packages.
2. **Existence check** — flags packages that don't exist in the registry at
   all (a hallucinated name waiting to be squatted).
3. **Typosquat / conflation similarity** — Levenshtein-based matching
   against popular packages, plus a conflation detector for names that
   look like two real packages mashed together (the `react-codeshift`
   pattern).
4. **Registry metadata red flags** — package age, weekly downloads,
   linked source repo, maintainer count.

Each package gets a 0-100 risk score and a `block` / `warn` / `pass`
verdict, with the exact reasons spelled out — not just a red flag with no
explanation.

## Usage

```bash
pip install -e .
unslop scan requirements.txt package.json              # scan everything listed
unslop scan requirements.txt --base origin/main        # only packages ADDED since origin/main
unslop scan package.json --json report.json --markdown comment.md
```

Exit codes: `0` nothing blocked, `1` at least one package blocked, `2` Unslop could not run
(bad git ref, unreadable manifest).

## GitHub Action

`.github/workflows/unslop.yml` runs on every pull request that touches a
`requirements*.txt` or `package.json`. It scans only the packages the PR adds,
posts (or updates) one PR comment with the findings, writes the same report to
the job summary, and fails the check if anything is blocked.

Design notes: it uses `pull_request` (not `pull_request_target`) so code from
forks never runs with secrets; the base branch name is passed through `env`, not
interpolated into the script; package names from the PR are sanitised before they
are printed, because the PR author controls them. On fork PRs the token is
read-only, so the comment step is skipped and the job summary carries the report.

## Project layout

```
unslop/
  unslop/
    registry_client.py   # PyPI + npm registry API calls
    heuristics.py        # risk scoring engine
    scanner.py           # manifest parsing + orchestration
    gitdiff.py           # which packages are new compared to a git ref
    report.py            # Markdown output for PR comments
    cli.py               # command-line interface
    data/
      known_hallucinations.json   # corpus of documented incidents
      popular_packages.json       # comparison set for typosquat detection
  tests/
    test_unslop.py                              # offline tests (registry calls are faked)
    demo_requirements.txt, demo_package.json    # demo fixtures
  .github/workflows/unslop.yml                  # PR check
```

Run the tests with `pip install pytest && pytest`.

## Roadmap

- Web dashboard (scan history, org-wide risk visibility)
- Multi-registry support (crates.io, Go modules)
- Community-reported hallucination corpus
- Real-time monitoring for AI coding agent sessions

## Sources

- USENIX Security 2025 — hallucinated package name taxonomy study
- Cloud Security Alliance — "Slopsquatting: AI Code Hallucinations Fuel
  Supply Chain Attacks" (April 2026)
- Aikido Security — `react-codeshift` incident writeup
- ReversingLabs — PromptMink campaign attribution
