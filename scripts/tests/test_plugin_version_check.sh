#!/usr/bin/env sh
#
# Behaviour tests for scripts/plugin-version-check.sh (feature 0102). The
# plugin-image workflow runs it before any build: the tag it was pushed with
# (plugin-semgrep-v<X.Y.Z>) must name the version the plugin declares in all
# three places, plugin.toml's `version`, the tag of plugin.toml's `image`, and
# pyproject.toml's `version`, so a tag can never publish an image whose code
# claims another version. On success it prints the version (the workflow's
# image tag); on any refusal stdout stays empty, so a caller that loses the
# exit code still gets no tag.
#
# Cases (each on a sandbox plugin dir whose manifests carry decoy keys, except
# repo-default):
#   match              all three agree with the tag: exit 0, prints X.Y.Z
#   tag-version        all three agree with each other, not with the tag
#   toml-version       plugin.toml version differs
#   image-tag          plugin.toml image tag differs
#   pyproject-version  pyproject.toml version differs
#   no-prefix          a tag without plugin-semgrep-v
#   not-xyz-*          versions that are not exactly X.Y.Z
#   missing-*          plugin.toml or pyproject.toml absent
#   no-argument        no tag at all: exit 2
#   repo-default       no dir argument, run from another directory: reads the
#                      repo's own plugins/semgrep, whose declared version passes
# Every refusal is exit 1, names what differs, and prints nothing on stdout.
#
# Usage: sh scripts/tests/test_plugin_version_check.sh
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
CHECK="$REPO_ROOT/scripts/plugin-version-check.sh"
require_file_or_bail check-script-exists "$CHECK"
make_sandbox

# plugin_dir <name> <toml-version> <image-tag> <pyproject-version> — a sandbox
# plugin dir laid out like plugins/semgrep. Decoys: api_version precedes
# version in [plugin], and a later table in pyproject.toml has its own version.
plugin_dir() {
    d="$SANDBOX/$1"
    mkdir -p "$d"
    printf '[plugin]\nname           = "semgrep"\napi_version    = "1.0"\nversion        = "%s"\n\n[runtime]\nimage           = "ghcr.io/bobinson/vulture-plugin-semgrep:%s"\n' \
        "$2" "$3" > "$d/plugin.toml"
    printf '[project]\nname = "vulture-plugin-semgrep"\nversion = "%s"\n\n[tool.decoy]\nversion = "9.9.9"\n' "$4" > "$d/pyproject.toml"
    printf '%s' "$d"
}

# run_check <tag> [dir] — run the check; sets RC, OUT and ERR.
run_check() {
    OUT=$(sh "$CHECK" "$@" 2> "$SANDBOX/err")
    RC=$?
    ERR=$(cat "$SANDBOX/err")
}

# expect_version <name> <version> <tag> [dir] — exit 0 printing <version>.
expect_version() {
    n=$1 v=$2
    shift 2
    run_check "$@"
    case "$RC:$OUT" in
        "0:$v") pass "$n" ;;
        *) fail "$n" "want rc 0 and '$v', got rc=$RC out='$OUT' err='$ERR'" ;;
    esac
}

# expect_refusal <name> <needle> <tag> [dir] — exit 1, <needle> on stderr,
# nothing on stdout.
expect_refusal() {
    n=$1 needle=$2
    shift 2
    run_check "$@"
    case "$RC:$OUT:$ERR" in
        1::*"$needle"*) pass "$n" ;;
        *) fail "$n" "want exit 1, empty stdout, stderr naming '$needle'; got rc=$RC out='$OUT' err='$ERR'" ;;
    esac
}

d=$(plugin_dir match 0.1.1 0.1.1 0.1.1)
expect_version match 0.1.1 plugin-semgrep-v0.1.1 "$d"
expect_refusal tag-version '0.1.2' plugin-semgrep-v0.1.2 "$d"
expect_refusal toml-version 'plugin.toml version' plugin-semgrep-v0.1.1 "$(plugin_dir tv 0.1.0 0.1.1 0.1.1)"
expect_refusal image-tag 'plugin.toml image' plugin-semgrep-v0.1.1 "$(plugin_dir it 0.1.1 0.1.0 0.1.1)"
expect_refusal pyproject-version 'pyproject.toml version' plugin-semgrep-v0.1.1 "$(plugin_dir pv 0.1.1 0.1.1 0.1.0)"
expect_refusal no-prefix 'plugin-semgrep-v' v0.1.1 "$d"

i=0
for bad in 0.1 0.1.1.1 0.1.1-rc1 '' ' 0.1.1' '0.1.1;id' 01.1.1x; do
    i=$((i + 1))
    expect_refusal "not-xyz-$i" 'X.Y.Z' "plugin-semgrep-v$bad" "$d"
done

for f in plugin.toml pyproject.toml; do
    m=$(plugin_dir "missing-$f" 0.1.1 0.1.1 0.1.1)
    rm -f "$m/$f"
    expect_refusal "missing-$f" "$f" plugin-semgrep-v0.1.1 "$m"
done

run_check
verdict no-argument "$([ "$RC" -eq 2 ] || echo "want exit 2 without a tag, got rc=$RC")"

repo_version=$(awk -F'"' '/^version *=/ { print $2; exit }' "$REPO_ROOT/plugins/semgrep/plugin.toml")
cd "$SANDBOX" || exit 1
expect_version repo-default "$repo_version" "plugin-semgrep-v$repo_version"

finish
