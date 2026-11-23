# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-11-21

Unslop is now a CI/CD security gate: slopsquatting detection plus vulnerabilities, secrets, an SBOM and a policy.

### Added
- `unslop gate`: one run that checks new dependencies, known vulnerabilities, secrets in added lines, writes an SBOM, applies a policy and returns one exit code.
- Known-vulnerability check for exactly pinned dependencies against OSV.dev, with severity from the advisory or computed from its CVSS v3 vector.
- Secret scanning of the lines a pull request adds (cloud, source-host, chat, payment and package-registry token formats, private keys, and a generic credential rule that only warns). Values are never printed; findings carry a fingerprint.
- CycloneDX 1.5 SBOM (`unslop sbom`, and `--sbom` on the gate), attached to the workflow run by the Action.
- Policy file `unslop.toml`: severity threshold, secret and slopsquat switches, `fail_on_error`, and waivers that need a reason and can expire. See `unslop.example.toml`.
- SARIF rules for vulnerable dependencies and secrets; the Action posts one combined comment.
- Dependency versions are parsed from requirements files, `package.json`, lockfiles and `pyproject.toml`.

### Changed
- The Action now runs the gate on every pull request (the path filter was removed so secrets are always checked) and stays quiet when there is nothing to report.

## [0.2.0] - 2026-11-15

### Added
- Diff-based scanning: `--base <ref>` checks only packages added since a git ref (version bumps are not "new").
- Scanning of install commands in Markdown (fenced and inline code), shell scripts, Dockerfiles and CI YAML.
- `package-lock.json` (v1, v2, v3) and `pyproject.toml` (PEP 621, dependency groups, Poetry) support.
- Reusable composite GitHub Action (`action.yml`): scans what a pull request adds, comments, uploads SARIF and fails the check on a block.
- `UNSLOP_TIMEOUT` environment variable to bound registry request time.
- `scripts/make_test_prs.sh` creates throwaway branches to test the Action with real pull requests.
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
