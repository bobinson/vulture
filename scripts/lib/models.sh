# shellcheck shell=bash
# Model-id conventions per provider, shared by start.sh (Mode A) and
# prod_start.sh (Mode B) so the two launchers cannot resolve a model differently.

# Default model per cloud provider: a real upstream id, never an alias.
# shellcheck disable=SC2034  # read by the launchers that source this file
DEFAULT_ANTHROPIC_MODEL="claude-sonnet-5-5"
# shellcheck disable=SC2034  # read by the launchers that source this file
DEFAULT_GEMINI_MODEL="gemini-2.5-flash"

# Apply the provider's model-id convention to an arbitrary model string.
# Used for the scan model and --validate-model alike: an unprefixed Gemini or
# Claude id would be routed to the wrong provider entirely.
#
# Aliases are EXPANDED here rather than exempted: the broker receives a BARE
# model id and cannot consult MODEL_MAP, so an unexpanded alias reaches Google
# or Anthropic verbatim and 404s. A TABLE, not an `if`, because a single
# hardcoded comparison makes every FUTURE alias born broken. Keep each table in
# step with MODEL_MAP in agents/shared/shared/llm/provider.py; parity in both
# directions is enforced by agents/shared/tests/unit/test_model_alias_shell_parity.py,
# which fails when an alias is added on either side alone.
normalize_model() {
    _nm_provider="$1"; _nm="$2"
    [[ -z "$_nm" ]] && { printf '%s' ""; return; }
    case "$_nm_provider" in
        gemini)
            case "$_nm" in
                gemini-pro)   _nm="gemini-2.5-pro" ;;
                gemini-flash) _nm="gemini-2.5-flash" ;;
            esac
            if [[ "$_nm" != litellm/* ]]; then
                _nm="litellm/gemini/${_nm#gemini/}"
            fi ;;
        anthropic)
            case "$_nm" in
                claude-sonnet) _nm="claude-sonnet-5-5" ;;
            esac
            if [[ "$_nm" != litellm/* ]]; then
                _nm="litellm/anthropic/${_nm#anthropic/}"
            fi ;;
        lmstudio)
            [[ "$_nm" != openai/* ]] && _nm="openai/$_nm" ;;
    esac
    printf '%s' "$_nm"
}

# The broker speaks to providers through native adapters and wants a BARE model
# id, so it strips the LiteLLM routing prefix normalize_model adds.
strip_broker_prefix() {
    _sb_provider="$1"; _sb="$2"
    case "$_sb_provider" in
        gemini)    _sb="${_sb#litellm/gemini/}"; _sb="${_sb#gemini/}" ;;
        lmstudio)  _sb="${_sb#openai/}" ;;
        anthropic) _sb="${_sb#litellm/anthropic/}"; _sb="${_sb#anthropic/}" ;;
    esac
    printf '%s' "$_sb"
}
