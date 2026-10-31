#!/usr/bin/env sh
# The tier-3 line of the launch summary must read VULTURE_USE_LLM with the same
# token list as the broker gate and the agents (scripts/lib/envflag.sh):
# on / true / 1 / yes, any case, surrounding whitespace ignored. Before this,
# `VULTURE_USE_LLM=on` ran the LLM tier while the summary claimed it had no effect.
#
# POSIX sh driver; the libs are bash and sourced in bash.
# Run: scripts/tests/test_tier3_llm_tokens.sh
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIB="$SCRIPT_DIR/../lib"
PASS=0
FAIL=0

state() {
    VULTURE_USE_LLM="$1" VULTURE_LLM_TIER3="$2" bash -c \
        ". '$LIB/envflag.sh'; . '$LIB/tier3.sh'; print_tier3_state '$3'" 2>&1
}

check() {
    got="$(state "$1" "$2" "$3")"
    if printf '%s' "$got" | grep -qF -- "$4"; then
        echo "  PASS [USE_LLM='$1' TIER3='$2' flag=$3]"; PASS=$((PASS + 1))
    else
        echo "  FAIL [USE_LLM='$1' TIER3='$2' flag=$3] expected: $4"
        echo "    output: $got"; FAIL=$((FAIL + 1))
    fi
}

echo "test_tier3_llm_tokens:"
for tok in true on ON 1 yes ' Yes '; do
    check "$tok" on 0 "Tier-3:    on"
    check "$tok" '' 0 "Tier-3:    off"
done
for tok in false off 0 no '' maybe; do
    check "$tok" on 1 "Note: --tier3 has no effect without an LLM provider."
done

echo ""
echo "  $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
