#!/usr/bin/env sh
# scripts/lib/hash.sh — portable hashing helpers shared by the release and
# smoke scripts. SOURCE this file (". scripts/lib/hash.sh"); do not execute it.
#
# Mirrors install.sh's two-tool pattern so a single edit covers every producer
# instead of the if/else being copy-pasted into each script.

# sha256_of FILE — print FILE's SHA-256 hex digest (just the hash, no filename).
# Uses GNU coreutils sha256sum (Linux) or BSD shasum (macOS); errors out if
# neither is on PATH (which the old inlined copies silently failed to do).
sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "error: neither sha256sum nor shasum found on PATH" >&2
        return 1
    fi
}

# sha256_verify_in_sums FILE SUMSFILE — verify FILE against the entry in SUMSFILE
# whose filename column is FILE's basename, fail-closed. Selects that entry with
# an EXACT awk field match ($2==basename) — NOT a regex — because PBS filenames
# contain '+' (an ERE quantifier) and '.' (ERE any-char), so the old
# `grep -E "[[:space:]]<base>$"` could mis-select or false-match. Mirrors
# build-release.sh's `awk -v f="$PBS_ASSET" '$2==f'` against the committed pin.
# The actual digest is computed via sha256_of, which carries the sha256sum/shasum
# two-tool portability AND the no-tool-on-PATH fail-closed case. Returns non-zero
# on: no matching entry, a digest mismatch, or no checksum tool present — so
# callers stay fail-closed.
sha256_verify_in_sums() {
    _svis_file=$1
    _svis_sums=$2
    _svis_base=$(basename "$_svis_file")
    # Exact field match on column 2 (the filename) — '+' and '.' are literal here,
    # unlike in an ERE. END{exit !f} fails closed when no line matched.
    _svis_exp=$(awk -v b="$_svis_base" '$2==b {print $1; f=1} END{exit !f}' "$_svis_sums") || {
        echo "error: no SHA256SUMS entry for $_svis_base in $_svis_sums" >&2
        return 1
    }
    _svis_act=$(sha256_of "$_svis_file") || return 1
    [ "$_svis_exp" = "$_svis_act" ] || {
        echo "error: SHA256 mismatch for $_svis_base (got $_svis_act want $_svis_exp)" >&2
        return 1
    }
}
