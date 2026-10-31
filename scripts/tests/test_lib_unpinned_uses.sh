#!/usr/bin/env sh
#
# Self-test of lib.sh's unpinned_uses (feature 0102), the guard behind every
# "actions are pinned" case: test_workflow_supply_chain.sh S3,
# test_release_workflows_static.sh and test_ci_lockfile_gate.sh. Those suites
# read the committed workflows, which are all pinned, so they cannot show that
# the guard would catch a regression. This suite feeds it each ref form:
#   U1  reports every ref that can move: a tag, a branch, a missing ref, a
#       remote action whose path merely contains `.github/actions/`, a
#       docker:// image with no `@sha256:` digest, a pin written only in the
#       trailing comment, and a SHA pin without the repo's `# vN` comment
#   U2  passes the immutable and in-repo forms: a 40-hex commit SHA with a
#       `# vN` comment (actions and reusable workflows), a docker:// image
#       pinned by `@sha256:` digest, and a `./` path
#
# Usage: sh scripts/tests/test_lib_unpinned_uses.sh
# Harness: scripts/tests/lib.sh (POSIX sh, set -u, "N passed, M failed", exit 1
# on any FAIL).

set -u

# shellcheck source=scripts/tests/lib.sh
. "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/lib.sh"

SHA=0123456789abcdef0123456789abcdef01234567
DIGEST=sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

make_sandbox

# outcome <line> — "reported" or "passed": what unpinned_uses makes of a
# workflow made of <line>.
outcome() {
    printf '%s\n' "$1" > "$SANDBOX/wf.yml"
    if [ -n "$(unpinned_uses "$SANDBOX/wf.yml")" ]; then echo reported; else echo passed; fi
}

# expect_all <name> <outcome> — pass <name> when every workflow line on stdin
# has <outcome>.
expect_all() {
    _d=""
    while IFS= read -r _l; do
        [ "$(outcome "$_l")" = "$2" ] || _d="$_d not-$2:[$_l]"
    done
    verdict "$1" "$_d"
}

expect_all u1-reports-movable-refs reported <<EOF
      - uses: actions/checkout@v4
      - uses: actions/checkout@main
      - uses: actions/checkout
      - uses: x/action@main
        uses: someorg/repo/.github/actions/x@main
        uses: someorg/repo/.github/actions/x
        uses: someorg/repo/x@main # not ./.github/actions/x
        uses: someorg/repo/x@main # uses: ./x
    uses: someorg/repo/.github/workflows/w.yml@v2
      - uses: docker://alpine:latest
      - uses: docker://alpine
      - uses: docker://ghcr.io/org/img:1.2
      - uses: docker://alpine@sha256:0123
      - uses: docker://alpine@${DIGEST}0
      - uses: docker://alpine@$SHA # v1
      - uses: docker://alpine:latest # @$DIGEST
      - uses: docker://alpine:latest # was docker://alpine@$DIGEST
      - uses: actions/checkout@main # @$SHA # v4
      - uses: actions/checkout@main # was actions/checkout@$SHA # v4
      - uses: actions/checkout@$SHA
EOF

expect_all u2-passes-pinned-and-in-repo-refs passed <<EOF
      - uses: actions/checkout@$SHA # v4
        uses: github/codeql-action/init@$SHA # v4.39.0
        uses: someorg/repo/.github/actions/x@$SHA # v1
    uses: someorg/repo/.github/workflows/w.yml@$SHA # v2
      - uses: ./.github/actions/setup-pinned-uv
    uses: ./.github/workflows/reusable.yml
      - uses: docker://alpine@$DIGEST
      - uses: docker://ghcr.io/org/img:1.2@$DIGEST
      - uses: docker://alpine@$DIGEST # 3.20
EOF

finish
