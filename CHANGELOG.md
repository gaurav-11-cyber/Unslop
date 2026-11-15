# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.2.0] - 2026-11-15

### Added
- Diff-based scanning: `--base <ref>` checks only packages added since a git ref (version bumps are not "new").
- Scanning of install commands in Markdown (fenced and inline code), shell scripts, Dockerfiles and CI YAML.
- `package-lock.json` (v1, v2, v3) and `pyproject.toml` (PEP 621, dependency groups, Poetry) support.
- GitHub Actions workflow that comments on pull requests and fails the check on a block.
- Markdown, JSON and SARIF 2.1.0 output; file and line locations for findings.
- On-disk registry cache (`--no-cache` to disable); retries and parallel lookups.
- Recognition of npm `0.0.1-security` placeholders (the original package was removed as malicious).
- Comparison lists of the top 5,000 PyPI and npm packages (`scripts/build_popular.py`).
- Evaluation harness with seeded OpenSSF and ranking datasets (`eval/`, results in `eval/results.md`).
- End-to-end CLI test script against the real registries (`scripts/e2e_cli.py`, 39 cases).

### Changed
- Typosquat detection now counts character edits (an adjacent swap is one edit) instead of a similarity ratio.
- Typosquat and conflation parameters were tuned on a dev split and checked on a held-out split; the conflation weight was lowered because it showed no recall on the evaluation sample.
- Data files moved into the package (`unslop/data/`) so installed copies find them.
- Python 3.11 or newer is required.

### Fixed
- A registry outage is reported as "could not verify" and no longer as "package does not exist".
- PyPI source-repository detection looks at every project URL, not only the first match.
- Well-known packages are no longer compared against each other for typosquats or conflations.
- Files starting with a UTF-8 byte-order mark are read correctly.
- `optionalDependencies` and `peerDependencies` in `package.json` are scanned.
- Local paths and `file:` lines in requirements files are ignored instead of reported as invalid names.
- The conflation hint no longer calls a weak name resemblance "a common AI hallucination pattern".

## [0.1.0]

- First prototype: CLI scanner for `requirements.txt` and `package.json`, registry metadata checks,
  typosquat and conflation heuristics, and a small corpus of documented incidents.
