#!/usr/bin/env sh
#
# Static guards for .github/workflows/plugin-image.yml (feature 0102): the
# workflow that builds, pushes, signs and attests the semgrep plugin image
# with the job's own GITHUB_TOKEN, so no personal registry token exists.
#
# Cases (on the comment-stripped workflow unless noted):
#   p1-tag-only        `on:` is exactly a push of plugin-semgrep-v* tags
#   p2-permissions     workflow level grants nothing; the one job grants
#                      exactly contents: read, packages: write, id-token: write,
#                      attestations: write
#   p3-one-gated-job   one job, `publish`, on a GitHub-hosted runner, gated by
#                      the plugin-release environment
#   p4-pinned          every `uses:` is pinned (lib.sh unpinned_uses, raw file)
#   p5-no-persist      every actions/checkout step sets persist-credentials: false
#   p6-no-cache        exactly the expected actions; no build cache in or out;
#                      QEMU and buildx set their cache inputs to false
#   p7-check-gates     the version check is an unconditional step fed the pushed
#                      tag, and the build's tag is that step's output
#   p8-platforms-tag   the build pushes exactly linux/amd64 and linux/arm64, to
#                      exactly one ref: the image repo plugin.toml pulls, at the
#                      checked version; never a latest tag
#   p9-by-digest       cosign signs and the attestation names the build digest
#   p10-token-only     every secret reference is secrets.GITHUB_TOKEN, and the
#                      ghcr.io login uses it
#   p11-cosign-pin     the cosign installer pin and cosign release equal
#                      release.yml's
#
# Usage: sh scripts/tests/test_plugin_image_workflow.sh
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

REPO_ROOT=$(repo_root "$0")
WF="$REPO_ROOT/.github/workflows/plugin-image.yml"
RELEASE_YML="$REPO_ROOT/.github/workflows/release.yml"
PLUGIN_TOML="$REPO_ROOT/plugins/semgrep/plugin.toml"
require_file_or_bail workflow-exists "$WF"
make_sandbox
BODY="$SANDBOX/wf"
noncomment "$WF" > "$BODY"

# has <text> <ere> — <text> has a line matching <ere>.
has() { printf '%s\n' "$1" | grep -Eq "$2"; }

# top_block <key> — the lines of a top-level key of the stripped workflow.
top_block() {
    awk -v k="$1:" '$1 == k && /^[^[:space:]]/ { f = 1; print; next }
        f && /^[^[:space:]]/ { f = 0 } f { print }' "$BODY"
}

# step_with <ere> — the first step (a `      - ` item) with a line matching
# <ere>, `\`-continued lines joined.
step_with() {
    awk -v re="$1" '/^      - / { if (hit) exit; buf = "" }
        { buf = buf $0 "\n" } $0 ~ re { hit = 1 }
        END { if (hit) printf "%s", buf }' "$BODY" | sed -e ':a' -e '/\\$/N; s/\\\n[[:space:]]*/ /; ta'
}

# value_of <key> <text> — the trimmed, unquoted value of `<key>:` in <text>.
value_of() {
    printf '%s\n' "$2" | sed -n "s/^[[:space:]-]*$1:[[:space:]]*//p" | head -n 1 | sed "s/[\"']//g; s/[[:space:]]*\$//"
}

# same <what> <ours> <release.yml's> — empty when both are equal and non-empty.
same() { [ -n "$2" ] && [ "$2" = "$3" ] || echo "$1 '$2' differs from release.yml '$3'"; }

expected_on=$(printf 'on:\n  push:\n    tags:\n      - plugin-semgrep-v*')
on_block=$(top_block on | sed "s/[\"']//g; s/[[:space:]]*\$//")
verdict p1-tag-only "$([ "$on_block" = "$expected_on" ] || echo "on: is '$on_block', want only a push of plugin-semgrep-v* tags")"

job=$(job_block "$WF" publish)
perms=$(printf '%s\n' "$job" | awk '/^    permissions:/ { f = 1; next } f && /^      [a-z-]+:/ { print $1 $2; next } f { f = 0 }' | sort | tr '\n' ' ')
verdict p2-permissions "$(
    grep -Eq '^permissions:[[:space:]]*\{\}[[:space:]]*$' "$BODY" || echo "workflow-level permissions are not {}"
    [ "$perms" = "attestations:write contents:read id-token:write packages:write " ] || echo "job permissions are '$perms'"
)"

jobs=$(top_block jobs | awk '/^  [A-Za-z0-9_-]+:[[:space:]]*$/ { print $1 }' | tr '\n' ' ')
verdict p3-one-gated-job "$(
    [ "$jobs" = "publish: " ] || echo "jobs are '$jobs', want only publish"
    has "$job" '^    environment:[[:space:]]*plugin-release[[:space:]]*$' || echo "publish is not gated by the plugin-release environment"
    has "$job" '^    runs-on:[[:space:]]*ubuntu-' || echo "publish does not run on a GitHub-hosted ubuntu runner"
)"

verdict p4-pinned "$(unpinned_uses "$WF" | sed 's/^/unpinned: /')"

verdict p5-no-persist "$(awk '/^      - / { if (c && !p) n++; c = 0; p = 0 }
    /uses:[[:space:]]*actions\/checkout@/ { c = 1 } /persist-credentials:[[:space:]]*false/ { p = 1 }
    END { if (c && !p) n++; if (n) print n " checkout step(s) without persist-credentials: false" }' "$BODY")"

actions=$(sed -n 's/^[[:space:]-]*uses:[[:space:]]*\([^@[:space:]]*\)@.*/\1/p' "$BODY" | sort | tr '\n' ' ')
verdict p6-no-cache "$(
    [ "$actions" = "actions/attest-build-provenance actions/checkout docker/build-push-action docker/login-action docker/setup-buildx-action docker/setup-qemu-action sigstore/cosign-installer " ] || echo "actions are '$actions'"
    grep -En 'cache-from|cache-to|actions/cache' "$BODY" | sed 's/^/cache at line /'
    [ "$(value_of cache-image "$(step_with 'docker/setup-qemu-action@')")" = false ] || echo "setup-qemu-action does not set cache-image: false"
    [ "$(value_of cache-binary "$(step_with 'docker/setup-buildx-action@')")" = false ] || echo "setup-buildx-action does not set cache-binary: false"
)"

check=$(step_with 'scripts/plugin-version-check\.sh')
check_id=$(value_of id "$check")
build=$(step_with 'docker/build-push-action@')
build_tags=$(value_of tags "$build" | tr -d ' ')
verdict p7-check-gates "$(
    [ -n "$check_id" ] || echo "the version check step has no id"
    has "$check" 'github\.ref_name|GITHUB_REF_NAME' || echo "the version check is not given the pushed tag"
    has "$check" '^[[:space:]-]*(if|continue-on-error):' && echo "the version check is conditional or may fail open"
    has "$build_tags" "steps\\.$check_id\\.outputs\\." || echo "the build's tag does not come from the version check"
)"

image_repo=$(awk -F'"' '/^image *=/ { sub(/:[^:]*$/, "", $2); print $2; exit }' "$PLUGIN_TOML")
wf_image=$(value_of IMAGE "$(top_block env)")
platforms=$(value_of platforms "$build" | tr ',' '\n' | tr -d ' ' | sort | tr '\n' ' ')
verdict p8-platforms-tag "$(
    [ "$platforms" = "linux/amd64 linux/arm64 " ] || echo "platforms are '$platforms'"
    [ "$build_tags" = "\${{env.IMAGE}}:\${{steps.$check_id.outputs.version}}" ] || echo "build tags are '$build_tags'"
    [ -n "$image_repo" ] && [ "$wf_image" = "$image_repo" ] || echo "workflow IMAGE '$wf_image' is not plugin.toml's image repo '$image_repo'"
    grep -En 'latest' "$BODY" | sed 's/^/latest at line /'
)"

build_id=$(value_of id "$build")
sign=$(step_with 'cosign[[:space:]]+sign')
digest_var=$(printf '%s\n' "$sign" | sed -n "s/^[[:space:]]*\([A-Z_][A-Z0-9_]*\):[[:space:]]*\${{[[:space:]]*steps\.$build_id\.outputs\.digest[[:space:]]*}}.*/\1/p" | head -n 1)
attest=$(step_with 'actions/attest-build-provenance@')
verdict p9-by-digest "$(
    [ -n "$build_id" ] || echo "the build step has no id"
    [ -n "$digest_var" ] || echo "the signing step takes no variable from the build digest"
    has "$sign" "cosign[[:space:]]+sign.*\\\$\\{IMAGE\\}@\"?\\\$\\{?$digest_var" || echo "cosign does not sign \${IMAGE}@\${$digest_var}"
    has "$attest" "subject-digest:.*steps\\.$build_id\\.outputs\\.digest" || echo "the attestation does not use the build digest"
    [ "$(value_of subject-name "$attest" | tr -d ' ')" = "\${{env.IMAGE}}" ] || echo "the attestation subject is not the image"
)"

login=$(step_with 'docker/login-action@')
verdict p10-token-only "$(
    total=$(grep -Eo '(^|[^A-Za-z0-9_])secrets' "$BODY" | wc -l)
    token=$(grep -Eo 'secrets\.GITHUB_TOKEN([^A-Za-z0-9_]|$)' "$BODY" | wc -l)
    [ "$total" -eq "$token" ] || echo "$((total - token)) secret reference(s) other than secrets.GITHUB_TOKEN"
    [ "$(value_of registry "$login")" = ghcr.io ] || echo "the login is not to ghcr.io"
    has "$login" 'password:[[:space:]]*\$\{\{[[:space:]]*secrets\.GITHUB_TOKEN[[:space:]]*\}\}' || echo "the login does not use GITHUB_TOKEN"
)"

pin() { noncomment "$1" | grep -Eo 'sigstore/cosign-installer@[0-9a-f]{40}' | sort -u; }
rel() { noncomment "$1" | sed -n "s/.*cosign-release:[[:space:]]*[\"']\{0,1\}\(v[0-9.]*\).*/\1/p" | sort -u; }
verdict p11-cosign-pin "$(
    same "cosign-installer pin" "$(pin "$WF")" "$(pin "$RELEASE_YML")"
    same "cosign release" "$(rel "$WF")" "$(rel "$RELEASE_YML")"
)"

finish
