#!/usr/bin/env sh
#
# E2E contract test for `vulture version` (feature 0055 follow-up).
#
# Business contract:
#   1. The release build injects the git tag into the version string via
#      `-ldflags "-X main.Version=<tag>"` (scripts/build-release.sh). Therefore
#      a binary built with that ldflag MUST report exactly that version.
#   2. A plain dev build (no ldflag) MUST report a non-release sentinel ("dev"),
#      NOT a hardcoded release-looking literal that lies about what it is.
#
# RED today: main.go hardcodes `fmt.Println("vulture v0.1.0")`, so the ldflag
# (which targets a non-existent main.Version symbol) is a silent no-op — both
# assertions fail.

set -eu

PASS=0
FAIL=0
pass() { PASS=$((PASS + 1)); printf 'PASS [%s]\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf 'FAIL [%s] %s\n' "$1" "$2"; }

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
BACKEND="$REPO_ROOT/backend"

if ! command -v go >/dev/null 2>&1; then
    printf 'SKIP: go toolchain not on PATH\n'
    exit 0
fi

TMP=$(mktemp -d 2>/dev/null || mktemp -d -t vulture-ver)
trap 'rm -rf "$TMP"' EXIT INT TERM

# Mirror the release build flags (scripts/build-release.sh): -tags installmode
# and the version-injecting ldflag.
INJECT="v9.9.9-e2e"
( cd "$BACKEND" && go build -tags installmode \
    -ldflags "-s -w -X main.Version=${INJECT}" \
    -o "$TMP/vulture-tagged" ./cmd/vulture ) \
  || { fail "build-tagged" "go build with version ldflag failed"; }

if [ -x "$TMP/vulture-tagged" ]; then
    got=$("$TMP/vulture-tagged" version 2>&1 || true)
    case "$got" in
        *"$INJECT"*) pass "ldflag-injected-version" ;;
        *) fail "ldflag-injected-version" "expected version output to contain '$INJECT', got '$got' (main.Version not wired to the printed string)" ;;
    esac
fi

# Plain dev build (no ldflag) -> sentinel default, not a fake release number.
( cd "$BACKEND" && go build -tags installmode -o "$TMP/vulture-plain" ./cmd/vulture ) \
  || { fail "build-plain" "plain go build failed"; }

if [ -x "$TMP/vulture-plain" ]; then
    got2=$("$TMP/vulture-plain" version 2>&1 || true)
    case "$got2" in
        *dev*) pass "default-dev-sentinel" ;;
        *) fail "default-dev-sentinel" "expected a 'dev' sentinel for an un-tagged build, got '$got2'" ;;
    esac
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
