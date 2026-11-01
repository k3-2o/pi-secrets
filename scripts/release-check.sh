#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PKG="@k3_2o/pi-secrets"
VERSION="${1:-}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/pi-secrets-release-XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

fail() {
	printf 'release-check: %s\n' "$*" >&2
	exit 1
}

note() {
	printf 'release-check: %s\n' "$*"
}

if [ -z "$VERSION" ]; then
	VERSION="$(node -p "require('./package.json').version")"
fi
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]] || fail "invalid semver: $VERSION"

pkg_version="$(node -p "require('./package.json').version")"
[ "$pkg_version" = "$VERSION" ] || fail "package.json is $pkg_version, expected $VERSION"

if git ls-files --error-unmatch package-lock.json >/dev/null 2>&1; then
	fail "package-lock.json is tracked; this repo uses Bun and does not publish a lockfile. Remove it before release."
fi

if npm view "$PKG@$VERSION" version --json >"$TMP/npm-view.out" 2>"$TMP/npm-view.err"; then
	fail "$PKG@$VERSION is already published"
fi
if ! grep -qE 'E404|404 Not Found|No match found' "$TMP/npm-view.err"; then
	fail "could not confirm $VERSION is unpublished (npm view failed)"
fi

header="$(grep -m1 '^## ' CHANGELOG.md || true)"
expected_header="## $VERSION — $(date +%F)"
[ "$header" = "$expected_header" ] || fail "CHANGELOG top section must be '$expected_header' (found '$header')"

note "local gate"
if ! just check >"$TMP/check.log" 2>&1; then
	tail -20 "$TMP/check.log" >&2
	fail "just check failed"
fi

note "pack manifest"
if ! npm pack --dry-run --json >"$TMP/pack.json" 2>"$TMP/pack.err"; then
	cat "$TMP/pack.err" >&2
	fail "npm pack --dry-run failed"
fi
node - "$TMP/pack.json" "$VERSION" <<'NODE'
const fs = require("node:fs");

const [file, version] = process.argv.slice(2);
const data = JSON.parse(fs.readFileSync(file, "utf8"));
const item = data[0];

if (!item) {
	console.error("release-check: npm pack returned no package");
	process.exit(1);
}
if (item.name !== "@k3_2o/pi-secrets") {
	console.error(`release-check: unexpected package name ${item.name}`);
	process.exit(1);
}
if (item.version !== version) {
	console.error(`release-check: tarball version ${item.version}, expected ${version}`);
	process.exit(1);
}

const expected = [
	"LICENSE",
	"README.md",
	"docs/explain.md",
	"index.ts",
	"package.json",
	"src/secrets/at-rest.ts",
	"src/secrets/dump-views.ts",
	"src/secrets/loaders.ts",
	"src/secrets/message-transform.ts",
	"src/secrets/obfuscator.ts",
	"src/secrets/patterns.ts",
	"src/secrets/placeholder-scan.ts",
	"src/secrets/placeholder.ts",
	"src/secrets/regex.ts",
	"src/secrets/registry-revision.ts",
	"src/secrets/replacement.ts",
	"src/secrets/stream-scrub.ts",
	"src/secrets/value-gate.ts",
	"src/settings.ts",
].sort();

const actual = item.files.map((entry) => entry.path).sort();
const missing = expected.filter((path) => !actual.includes(path));
const extra = actual.filter((path) => !expected.includes(path));

if (missing.length > 0 || extra.length > 0) {
	console.error(`release-check: tarball manifest mismatch; missing=${JSON.stringify(missing)} extra=${JSON.stringify(extra)}`);
	process.exit(1);
}
if (item.entryCount !== expected.length) {
	console.error(`release-check: tarball entryCount ${item.entryCount}, expected ${expected.length}`);
	process.exit(1);
}

console.log(`release-check: tarball ${item.entryCount} files, shasum ${item.shasum}`);
NODE

note "secret scan"
secret_re='sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----'
hits="$(git grep -nEI "$secret_re" -- . ':(exclude)test/**' ':(exclude).agents/**' ':(exclude)package-lock.json' ':(exclude)node_modules/**' || true)"
if [ -n "$hits" ]; then
	filtered="$(printf '%s\n' "$hits" | grep -vE 'sk-smoke' || true)"
	if [ -n "$filtered" ]; then
		printf '%s\n' "$filtered" | cut -d: -f1-2 | sed 's/^/release-check: possible secret at /' >&2
		fail "secret scan found candidate credentials"
	fi
fi

note "changed paths"
while IFS= read -r line; do
	[ -z "$line" ] && continue
	path="${line:3}"
	if ! [[ "$path" =~ ^(CHANGELOG\.md|package\.json|package-lock\.json)$ ]]; then
		fail "unexpected changed path: $path"
	fi
done < <(git status --porcelain=v1)

note "ok: $PKG@$VERSION is ready to tag"
