# shellcheck shell=sh
# scripts/uv-version.sh — feature 0056 (M8).
#
# THE single source of truth for the pinned uv version. SOURCE this, never run
# it: it sets one variable and has no shebang, no exec, and no command logic, so
# it is safe to '. ' from a `set -eu` script. Bumping uv = edit this one line
# (then one relock PR). Read by scripts/gen-lockfile.sh and by the
# .github/actions/setup-pinned-uv composite action used in CI.
#
# A different uv can resolve different versions or order hashes differently,
# which would make scripts/check-lockfile.sh's re-derive-and-diff flap; the pin
# keeps lockfile regeneration reproducible.
# shellcheck disable=SC2034  # consumed by the sourcing script (gen-lockfile.sh) and the setup-pinned-uv action
UV_VERSION=0.11.21
