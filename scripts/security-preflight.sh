#!/usr/bin/env sh
#
# scripts/security-preflight.sh — 0056 C4 pre-tag Python-deps security gate.
#
# The sixth gate run by scripts/release-preflight.sh. It gives the release
# manager the open-vulnerability picture for the LOCKED Python set BEFORE a tag
# is cut, mirroring the CI Trivy verdict (Trivy stays the broad hard gate; this
# is the Python-deps subset, surfaced early on the laptop).
#
# What it does:
#   1. `pip-audit -r <requirements>` over the locked set, honoring the
#      .pip-audit-ignore allowlist. A HIGH/CRITICAL finding with NO matching
#      waiver FAILS the gate.
#   2. best-effort `gh api .../dependabot/alerts?state=open` for the alerts the
#      Security tab holds (advisory enrichment).
#
# Tooling-absent policy (audit M2; LLD §5 C4 / §11):
#   - `pip-audit` ITSELF absent       -> FAIL the gate. We refuse to cut a release
#                                        with no local dependency audit available.
#   - `gh` / token / network / a 403  -> LOUD WARN, and the gate REFUSES to
#     from the alerts API               proceed unless VULTURE_ACK_NO_ALERTS=true
#                                        is set. It then degrades to pip-audit-only.
#   - un-waived HIGH/CRITICAL finding -> FAIL the gate.
#
# Dependabot-alerts token (audit M2 — IMPORTANT):
#   The /repos/<owner>/<repo>/dependabot/alerts endpoint is NOT readable by the
#   default GITHUB_TOKEN: the `security-events: read` scope is CODE-SCANNING only
#   and the endpoint returns 403 even at `write-all`. Reading Dependabot alerts
#   requires a PERSONAL ACCESS TOKEN or GitHub App token with fine-grained
#   `security_events: read` (a.k.a. Dependabot alerts: read) on this repo. Export
#   it for `gh` (e.g. `GH_TOKEN=<pat> scripts/release-preflight.sh`). A 403 is
#   treated as "no token", NOT "network down" -> loud warn, never a hard fail.
#
# Waiver grammar (audit M9):
#   .pip-audit-ignore lines beginning with an advisory ID — CVE-, GHSA-, PYSEC-,
#   or OSV- — are parsed (the rest of the line is the justification + expiry) and
#   forwarded to pip-audit as `--ignore-vuln <ID>`. The OLD parser accepted only
#   `^CVE-`, which silently dropped GHSA/PYSEC-only advisories and false-blocked
#   the gate; this accepts all four prefixes.
#
# POSIX sh, no bashisms. Tiny functions (cyclomatic < 5), DRY.
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH='' cd -- "$SCRIPT_DIR/.." && pwd)

# Inputs (overridable for tests; default to the repo's real paths).
REQUIREMENTS=${VULTURE_REQUIREMENTS:-"$REPO_ROOT/agents/requirements-frozen.txt"}
IGNORE_FILE=${VULTURE_PIP_AUDIT_IGNORE:-"$REPO_ROOT/.pip-audit-ignore"}
# The repo to query for Dependabot alerts (best-effort).
ALERTS_REPO=${VULTURE_ALERTS_REPO:-"bobinson/vulture"}

# warn <msg> — a LOUD, unmissable warning on stderr (does NOT exit).
warn() {
    echo "security-preflight: WARNING — $1" >&2
}

# die <msg> — report the tripped gate on stderr and exit LOUDLY (non-zero).
die() {
    echo "security-preflight: FAILED — $1" >&2
    exit 1
}

# waiver_args — print the `--ignore-vuln <ID>` flags parsed from IGNORE_FILE.
# Accepts CVE-/GHSA-/PYSEC-/OSV- prefixed lines (M9), stripping a trailing
# `: justification`. Empty when the file is absent or holds no advisory lines.
waiver_args() {
    [ -f "$IGNORE_FILE" ] || return 0
    # Match an advisory ID at the start of a line (optionally leading space),
    # emit `--ignore-vuln <ID>`. The ID is field 1 up to the first ':' or space.
    awk '
        /^[[:space:]]*(CVE|GHSA|PYSEC|OSV)-/ {
            line=$0
            sub(/^[[:space:]]+/, "", line)
            split(line, parts, /[: \t]/)
            if (parts[1] != "") print "--ignore-vuln " parts[1]
        }
    ' "$IGNORE_FILE"
}

# run_pip_audit — run pip-audit over the locked set with the parsed waivers.
# FAILS the gate if pip-audit is absent (M2) or reports an un-waived finding.
run_pip_audit() {
    if ! command -v pip-audit >/dev/null 2>&1; then
        die "pip-audit is not installed — refusing to tag with no local dependency audit (install it: 'pipx install pip-audit'). Trivy remains the CI hard gate."
    fi
    [ -f "$REQUIREMENTS" ] || die "requirements file not found: $REQUIREMENTS"
    # shellcheck disable=SC2046  # word-splitting the waiver flags is intentional
    set -- $(waiver_args)
    echo "==> pip-audit -r $REQUIREMENTS ($# waiver flag-words)"
    if pip-audit -r "$REQUIREMENTS" "$@"; then
        echo "    pip-audit: no un-waived advisories"
    else
        die "pip-audit reported un-waived HIGH/CRITICAL advisories (waive in .pip-audit-ignore with a date-stamped justification, or fix the dep)"
    fi
}

# check_alerts — best-effort Dependabot-alerts enrichment. Missing gh / token /
# network / a 403 => LOUD WARN, and the gate REFUSES to proceed unless
# VULTURE_ACK_NO_ALERTS=true is set (M2). Never a hard fail on the alert read
# itself — the refusal is on the UNACKNOWLEDGED blind spot, acknowledged away by
# the env flag.
check_alerts() {
    # Fetch the alert feed EXACTLY ONCE and branch on that single result. A prior
    # probe-then-fetch design double-hit the API and was TOCTOU-unsafe: if the
    # probe passed but the real read 403'd/rate-limited in between, the `|| true`
    # swallowed it and the gate printed an empty list and PASSED — a false
    # all-clear. One read, one decision.
    if command -v gh >/dev/null 2>&1 \
       && alerts=$(gh api "/repos/$ALERTS_REPO/dependabot/alerts?state=open" \
            --jq '.[] | "    [" + (.security_advisory.severity // "?") + "] " + (.security_advisory.ghsa_id // "?") + " — " + (.dependency.package.name // "?")' 2>/dev/null); then
        echo "==> Dependabot alerts (open):"
        [ -n "$alerts" ] && echo "$alerts"
        return 0
    fi
    # gh absent, unauthenticated, 403, or network down: the alert feed is blind.
    warn "could not read Dependabot alerts for $ALERTS_REPO."
    warn "the default GITHUB_TOKEN CANNOT read /dependabot/alerts (403); a PAT/App"
    warn "token with 'security_events: read' is required (export it for gh)."
    warn "this gate is therefore running pip-audit ONLY and is BLIND to GHSA-only"
    warn "or transitive advisories that pip-audit cannot see."
    if [ "${VULTURE_ACK_NO_ALERTS:-}" = "true" ]; then
        warn "VULTURE_ACK_NO_ALERTS=true set — proceeding with pip-audit only."
        return 0
    fi
    die "Dependabot-alerts feed unavailable and not acknowledged. Provide a PAT (GH_TOKEN with security_events:read), or set VULTURE_ACK_NO_ALERTS=true to proceed on pip-audit alone (you accept the blind spot)."
}

echo "==> security preflight (pip-audit + Dependabot alerts)"
# pip-audit is the core auditor (fails closed if absent); the alert feed is
# optional enrichment (loud warn + ack-gated). Run the alert check first so its
# acknowledgement requirement is evaluated before the longer pip-audit run.
check_alerts
run_pip_audit
echo "==> security preflight: PASSED"
