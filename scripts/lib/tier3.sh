# shellcheck shell=bash
# The --tier3 / --deep launcher flag, shared by start.sh (Mode A) and
# prod_start.sh (Mode B) so the two cannot report it differently.
#
# Tier 3 widens what the LLM phase sees, from skill-flagged + entry/config files
# to the long tail of the tree. It is still bounded by VULTURE_LLM_MAX_FILES,
# VULTURE_LLM_BUDGET_USD and the prose limits, a per-audit `llm_tier3` setting
# still overrides it, and the deterministic skills scan every file regardless.

# Requires scripts/lib/envflag.sh (env_flag_on), sourced first by both launchers:
# every switch here takes its one token list (on / true / 1 / yes, any case).

# True when VULTURE_LLM_TIER3 is on (the agent's _llm_tier3_enabled reads the same).
tier3_enabled() {
    env_flag_on "${VULTURE_LLM_TIER3:-}"
}

# The tier-3 line of the launch summary. Call it AFTER provider resolution:
# the state is only meaningful when the LLM phase is enabled.
# $1 = 1 when --tier3/--deep was passed on the command line.
print_tier3_state() {
    if env_flag_on "${VULTURE_USE_LLM:-}"; then
        if tier3_enabled; then
            echo "  Tier-3:    on (LLM sweep past skill-flagged + entry/config files; capped by VULTURE_LLM_MAX_FILES and the budget)"
        else
            echo "  Tier-3:    off"
        fi
    elif [[ "${1:-0}" == "1" ]]; then
        echo "  Note: --tier3 has no effect without an LLM provider."
    fi
}
