#!/usr/bin/env sh
#
# plugin-version-check.sh <plugin-semgrep-vX.Y.Z> [plugin-dir] (feature 0102)
#
# The tag's version must equal plugin.toml's [plugin] version, the tag of its
# [runtime] image and pyproject.toml's [project] version (plugin-dir defaults
# to plugins/semgrep). Prints X.Y.Z and exits 0; otherwise prints the reason on
# stderr, nothing on stdout, and exits 1 (2 on a usage error).

set -eu

PREFIX=plugin-semgrep-v

die() { printf 'plugin-version-check: %s\n' "$1" >&2; exit 1; }

# toml_value <file> <table> <key> — the double-quoted value of <key> in [<table>].
toml_value() {
    awk -F'"' -v t="[$2]" -v k="$3" '/^\[/ { in_t = ($0 == t); next }
        in_t && $1 ~ "^" k " *= *$" { print $2; exit }' "$1"
}

# expect <what> <declared> <version> — refuse unless <declared> is <version>.
expect() {
    [ "$2" = "$3" ] || die "$1 '$2' does not match the tag's version '$3'"
}

[ $# -ge 1 ] || { echo "usage: $0 <${PREFIX}X.Y.Z> [plugin-dir]" >&2; exit 2; }
printf '%s\n' "$1" | grep -Eqx "${PREFIX}[0-9]+\.[0-9]+\.[0-9]+" || die "tag '$1' is not ${PREFIX}X.Y.Z"
version=${1#"$PREFIX"}
dir=${2:-$(dirname -- "$0")/../plugins/semgrep}
for f in plugin.toml pyproject.toml; do
    [ -f "$dir/$f" ] || die "$f not found in $dir"
done

image=$(toml_value "$dir/plugin.toml" runtime image)
expect "plugin.toml version" "$(toml_value "$dir/plugin.toml" plugin version)" "$version"
expect "plugin.toml image tag" "${image##*:}" "$version"
expect "pyproject.toml version" "$(toml_value "$dir/pyproject.toml" project version)" "$version"
printf '%s\n' "$version"
