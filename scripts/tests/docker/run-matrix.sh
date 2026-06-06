#!/usr/bin/env bash
# Run the full cross-distro installer e2e matrix (Ubuntu 24.04 + Fedora 41,
# with/without Python 3.12) via run-one.sh. Local convenience + CI fallback.
# Exits non-zero if any scenario fails.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)

CASES=(
    "ubuntu no-python"        "ubuntu py-no-optin"   "ubuntu py-optin-hashed"
    "ubuntu py-optin-hashless" "ubuntu py-no-venv"
    "fedora no-python"        "fedora py-no-optin"   "fedora py-optin-hashed"
    "fedora py-optin-hashless"
)

pass=0; fail=0; failed=""
for c in "${CASES[@]}"; do
    # shellcheck disable=SC2086
    set -- $c
    echo "================================================================"
    if "$HERE/run-one.sh" "$1" "$2"; then pass=$((pass + 1)); else fail=$((fail + 1)); failed="$failed $1/$2"; fi
done

echo "================================================================"
echo "matrix: $pass passed, $fail failed"
if [ "$fail" -ne 0 ]; then echo "FAILED:$failed"; exit 1; fi
