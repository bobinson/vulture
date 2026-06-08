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
