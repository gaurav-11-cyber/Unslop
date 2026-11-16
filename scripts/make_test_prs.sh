#!/usr/bin/env bash
# Create (or delete) throwaway branches, one per scenario, to open test pull requests against main.
#   bash scripts/make_test_prs.sh create     push the branches and print PR links
#   bash scripts/make_test_prs.sh cleanup    delete the branches locally and on origin
# Never merge these PRs: they contain deliberately fake dependencies.
set -euo pipefail

cmd="${1:-}"
branches="test/pr-manifest test/pr-npm-incident test/pr-docs test/pr-docs-unknown test/pr-lockfile test/pr-pyproject test/pr-clean test/pr-unrelated"

[ "$cmd" = create ] || [ "$cmd" = cleanup ] || { echo "usage: $0 create|cleanup"; exit 2; }
[ -z "$(git status --porcelain)" ] || { echo "working tree is not clean"; exit 1; }
start="$(git rev-parse --abbrev-ref HEAD)"
base_url="$(git remote get-url origin | sed -E 's#^git@github.com:#https://github.com/#; s#\.git$##')"

if [ "$cmd" = cleanup ]; then
  git switch -q main
  for b in $branches; do
    git branch -D "$b" > /dev/null 2>&1 || true
    git push origin --delete "$b" > /dev/null 2>&1 || true
  done
  echo "test branches deleted. Close the test PRs on GitHub if they are still open."
  exit 0
fi

git switch -q main
make_branch() {   # name, file, content, message
  git switch -q -c "$1" main
  mkdir -p "$(dirname "$2")"
  printf '%s\n' "$3" > "$2"
  git add "$2"
  git commit -qm "$4"
  git push -q -u origin "$1"
  git switch -q main
  echo "  $1  ->  $base_url/compare/main...$1?expand=1"
}

echo "Pushing test branches (open one PR per branch, base = main):"
make_branch test/pr-manifest     examples/requirements.txt 'requests
reqeusts' "test: typosquat in requirements.txt (expect BLOCK, check fails)"
make_branch test/pr-npm-incident examples/package.json '{"dependencies": {"react-codeshift": "1.0.0"}}' "test: documented incident in package.json (expect BLOCK)"
make_branch test/pr-docs         examples/SKILL.md '# Setup
```bash
npm install react-codeshift
```' "test: install command in an agent skill file (expect BLOCK with file:line)"
make_branch test/pr-docs-unknown examples/setup.sh 'pip install zzz-fake-pkg-qwerty-123' "test: unknown package in a script (expect WARN, check passes)"
make_branch test/pr-lockfile     examples/package-lock.json '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/react-codeshift": {}}}' "test: incident in a lockfile (expect BLOCK)"
make_branch test/pr-pyproject    examples/pyproject.toml '[project]
dependencies = ["reqeusts"]' "test: typosquat in pyproject.toml (expect BLOCK)"
make_branch test/pr-clean        examples/requirements.txt 'flask
requests' "test: only popular packages (expect PASS)"
make_branch test/pr-unrelated    examples/notes.txt 'nothing to scan here' "test: unrelated file (expect: the workflow does not run)"
git switch -q "$start"
echo "Done. After testing: bash scripts/make_test_prs.sh cleanup"
