# shellcheck shell=bash
# The --tier3 / --deep launcher flag, shared by start.sh (Mode A) and
# prod_start.sh (Mode B) so the two cannot report it differently.
#
# Tier 3 widens what the LLM phase sees, from skill-flagged + entry/config files
# to the long tail of the tree. It is still bounded by VULTURE_LLM_MAX_FILES,
# VULTURE_LLM_BUDGET_USD and the prose limits, a per-audit `llm_tier3` setting
# still overrides it, and the deterministic skills scan every file regardless.

# True when VULTURE_LLM_TIER3 is on. Same tokens as the agent's reader
# (audit_runner._llm_tier3_enabled): on / true / 1 / yes, any case.
tier3_enabled() {
    case "$(printf '%s' "${VULTURE_LLM_TIER3:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')" in
        on|true|1|yes) return 0 ;;
    esac
    return 1
}

# The tier-3 line of the launch summary. Call it AFTER provider resolution:
# the state is only meaningful when the LLM phase is enabled.
# $1 = 1 when --tier3/--deep was passed on the command line.
print_tier3_state() {
    if [[ "${VULTURE_USE_LLM:-false}" == "true" ]]; then
        if tier3_enabled; then
            echo "  Tier-3:    on (LLM sweep past skill-flagged + entry/config files; capped by VULTURE_LLM_MAX_FILES and the budget)"
        else
            echo "  Tier-3:    off"
        fi
    elif [[ "${1:-0}" == "1" ]]; then
        echo "  Note: --tier3 has no effect without an LLM provider."
    fi
}
