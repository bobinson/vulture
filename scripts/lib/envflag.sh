#!/usr/bin/env sh
# scripts/lib/envflag.sh — boolean env-switch parsing for the launchers.
# SOURCE this file; do not execute it.
#
# One token list for a switch the shell, the Go backend (config.ParseFlag) and
# the agents (shared.env) all read: on/true/1/yes are on, case-insensitive,
# surrounding whitespace ignored. Anything else — blank, off/false/0/no, or an
# unrecognised value — is off, the default of every switch read here
# (VULTURE_USE_LLM). Pinned against backend/internal/config/testdata/
# flag_tokens_0074.json by scripts/tests/test_env_flag.sh.

# env_flag_on VALUE — succeed when VALUE is an "on" token.
env_flag_on() {
    case "$(printf '%s' "$1" | tr -d '[:space:]' | tr '[:upper:]' '[:lower:]')" in
        on|true|1|yes) return 0 ;;
    esac
    return 1
}

# env_flag_word VALUE — print "true" or "false" for VALUE (for display/.env).
env_flag_word() {
    if env_flag_on "$1"; then echo true; else echo false; fi
}
