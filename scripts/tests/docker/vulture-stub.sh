#!/usr/bin/env sh
# Minimal stand-in for the Go `vulture` binary, used by the cross-distro
# installer e2e tests (feature 0055). We are testing install.sh, not the Go
# binary, so this stub only needs to satisfy what install.sh's verify_install
# and the runner assertions call: version / doctor / uninstall / scan.
#
# `doctor` mirrors the real check: it returns 0 only when the bundled/built
# Python interpreter exists at runtime/python/bin/python3.12 (so a successful
# system-Python install flips doctor 2 -> 0), else WARN/2.
set -u
# Resolve the install root from this binary's location ($HOME/.vulture/bin/vulture).
# Clear CDPATH so `cd` cannot resolve to an unexpected directory.
CDPATH=''
HOME_DIR=$(cd -- "$(dirname -- "$0")/.." 2>/dev/null && pwd || echo "${VULTURE_HOME:-$HOME/.vulture}")

case "${1:-}" in
    version|--version|-v)
        cat "$HOME_DIR/VERSION" 2>/dev/null || echo "vulture-stub (unknown)"
        ;;
    doctor)
        if [ -x "$HOME_DIR/runtime/python/bin/python3.12" ]; then
            echo "python runtime: OK ($HOME_DIR/runtime/python/bin/python3.12)"
            exit 0
        fi
        echo "python runtime: WARN — not present (agents need Docker or system-Python install)" >&2
        exit 2
        ;;
    uninstall)
        rm -rf "$HOME_DIR"
        rm -f "$HOME/.local/bin/vulture"
        echo "uninstalled $HOME_DIR"
        ;;
    scan)
        echo "scan (stub): ok"
        ;;
    *)
        echo "vulture-stub: unhandled command '${1:-}'" >&2
        ;;
esac
