# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security tab -> Report a vulnerability** (https://github.com/gaurav-11-cyber/Unslop/security/advisories/new).
Do not open a public issue for a vulnerability. This is a personal project, so replies are best effort.

## Supported versions

| Version | Supported |
|---|---|
| 0.2.x | Yes |
| < 0.2 | No |

## Scope and design notes

- Unslop reads manifests, lockfiles, docs and scripts that may come from untrusted pull requests.
  It only **parses** them (JSON, TOML, text, `shlex`); it never executes install commands or file contents.
- Package names from those files are treated as untrusted: names that are not valid PyPI/npm names are never sent to a
  registry, and text is sanitised before it goes into PR comments, SARIF or terminal output.
- The only network calls are to the public PyPI and npm registries (plus pypistats.org and api.npmjs.org for download counts).
- Unslop is a heuristic gate, not proof of safety. A pass does not mean a package is safe, and a block does not prove malice.
  See `eval/results.md` for measured accuracy and its limits.
