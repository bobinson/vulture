#!/usr/bin/env sh
#
# Vulture native installer — feature 0044.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/bobinson/vulture/main/install.sh | sh
#
# Environment:
#   VULTURE_HOME            Install root (default: ~/.vulture)
#   VULTURE_VERSION         Pin a specific tag (CANNOT downgrade below the
#                           hardcoded FALLBACK_TAG below — see plan H2)
#   VULTURE_OFFLINE_TARBALL Pre-downloaded tarball; companion .sig and
#                           SHA256SUMS must sit at the same path
#   VULTURE_REQUIRE_COSIGN  If true, refuse to install without cosign
#   VULTURE_ALLOW_UNSIGNED  If true (and cosign unavailable), allow
#                           SHA-only verification
#   VULTURE_PIP_INDEX_URL   Alternate PyPI mirror (https:// strongly
#                           preferred; a plaintext http:// mirror is
#                           allowed but disables TLS verification for
#                           that host — see install_python_deps)
#   VULTURE_NO_UPDATE_CHECK Disable doctor's GH-API call after install
#   VULTURE_ALLOW_DOWNGRADE  Allow VULTURE_VERSION older than fallback
#
# This script is shellcheck-clean and POSIX-sh (no bashisms).

set -eu

# Fallback tag bumped on every release per plan H2. install.sh refuses
# any older version (see resolve_version).
FALLBACK_TAG="v0.1.0"
REPO_OWNER="bobinson"
REPO_NAME="vulture"
REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}"
RELEASES_API="https://api.github.com/repos/${REPO_OWNER}/${REPO_NAME}/releases/latest"

log()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }

# ─── shared helpers (single source of truth; used in >1 place) ──────────────

# resolve_path PATH — print PATH with symlinks resolved (best-effort).
# Falls back to the literal path when readlink is absent or fails.
resolve_path() {
    if command -v readlink >/dev/null 2>&1; then
        readlink -f "$1" 2>/dev/null || printf '%s' "$1"
    else
        printf '%s' "$1"
    fi
}

# reject_if_system_dir PATH — return non-zero if PATH is, or lives
# directly under, a system directory we must never install into.
# NOTE: /root is rejected only as an *exact* target, not as a parent —
# a root user's ~/.vulture (= /root/.vulture) is a legitimate location,
# so /root/* is intentionally NOT blacklisted (it would break root /
# container installs that use the default $HOME/.vulture).
reject_if_system_dir() {
    case "$1" in
        /|/bin|/sbin|/lib|/lib64|/boot|/sys|/proc|/dev|/root|/etc|/usr|/var)
            return 1 ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*|/boot/*|/sys/*|/proc/*|/dev/*|/etc/*|/usr/*|/var/*)
            return 1 ;;
    esac
    return 0
}

# fetch URL OUTFILE — download with bounded retries + a hard timeout so a
# transient network blip backs off instead of failing the whole install.
fetch() {
    curl -fsSL --retry 3 --retry-delay 2 --retry-connrefused \
        --max-time 300 -o "$2" "$1"
}

# cleanup — EXIT trap (installed by main). Rolls back a half-applied
# upgrade and removes transient staging/download dirs. State globals
# (OLD_HOME, NEW_HOME, DL_TMP, INSTALL_COMMITTED) are set as the install
# progresses; until commit_install marks the swap durable, an abort here
# restores the previous version so a failed step never leaves the user
# with a destroyed old install and a half-built new one.
cleanup() {
    code=$?
    if [ "${INSTALL_COMMITTED:-0}" != "1" ] \
       && [ -n "${OLD_HOME:-}" ] && [ -d "${OLD_HOME:-/nonexistent}" ]; then
        warn "install did not complete; rolling back to the previous version"
        rm -rf "$VULTURE_HOME" 2>/dev/null || true
        mv "$OLD_HOME" "$VULTURE_HOME" 2>/dev/null || true
    fi
    [ -n "${NEW_HOME:-}" ] && rm -rf "${NEW_HOME:-/nonexistent}" 2>/dev/null || true
    [ -n "${DL_TMP:-}" ]   && rm -rf "${DL_TMP:-/nonexistent}" 2>/dev/null || true
    return "$code"
}

# ─── 1. detect_platform ────────────────────────────────────────────────────
detect_platform() {
    UNAME_S=$(uname -s 2>/dev/null || echo unknown)
    UNAME_M=$(uname -m 2>/dev/null || echo unknown)
    case "$UNAME_S" in
        Linux)  OS=linux ;;
        Darwin) OS=darwin ;;
        *) err "unsupported OS: $UNAME_S (Linux/macOS only)" ;;
    esac
    case "$UNAME_M" in
        x86_64|amd64) ARCH=amd64 ;;
        aarch64|arm64) ARCH=arm64 ;;
        *) err "unsupported architecture: $UNAME_M" ;;
    esac
    log "detected platform: ${OS}-${ARCH}"
}

# ─── 2. validate_home ──────────────────────────────────────────────────────
validate_home() {
    : "${VULTURE_HOME:=$HOME/.vulture}"
    case "$VULTURE_HOME" in
        */../*|*..)     err "VULTURE_HOME contains '..': $VULTURE_HOME" ;;
    esac
    case "$VULTURE_HOME" in
        *[!A-Za-z0-9_./-]*)
            err "VULTURE_HOME contains unsafe characters: $VULTURE_HOME" ;;
    esac
    # Resolve symlinks before checking blacklist.
    RESOLVED=$(resolve_path "$VULTURE_HOME")
    reject_if_system_dir "$RESOLVED" \
        || err "VULTURE_HOME resolves to a system directory: $RESOLVED"
    if [ -e "$VULTURE_HOME" ]; then
        OWNER=$(ls -ldn "$VULTURE_HOME" 2>/dev/null | awk '{print $3}')
        ME=$(id -u 2>/dev/null || echo 0)
        if [ -n "$OWNER" ] && [ "$OWNER" != "$ME" ]; then
            err "$VULTURE_HOME is owned by uid $OWNER, not $ME"
        fi
    fi
    log "VULTURE_HOME validated: $VULTURE_HOME"
}

# ─── 3. resolve_version ────────────────────────────────────────────────────
resolve_version() {
    if [ -n "${VULTURE_VERSION:-}" ]; then
        VERSION=$VULTURE_VERSION
    elif command -v curl >/dev/null 2>&1; then
        VERSION=$(curl -fsSL --retry 3 --retry-delay 2 --max-time 30 \
            "$RELEASES_API" 2>/dev/null \
            | grep -E '"tag_name"' | head -1 \
            | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/' \
            || true)
    fi
    if [ -z "${VERSION:-}" ]; then
        warn "GitHub API unreachable; falling back to $FALLBACK_TAG"
        VERSION=$FALLBACK_TAG
    fi
    # Fail closed: refuse to install older than fallback unless explicitly allowed.
    if [ "$VERSION" != "$FALLBACK_TAG" ] && [ "${VULTURE_ALLOW_DOWNGRADE:-}" != "true" ]; then
        # Lexicographic compare is good enough for vX.Y.Z tags.
        if [ "$(printf '%s\n%s\n' "$VERSION" "$FALLBACK_TAG" | sort -V | head -1)" = "$VERSION" ] \
           && [ "$VERSION" != "$FALLBACK_TAG" ]; then
            err "refusing to downgrade to $VERSION (fallback=$FALLBACK_TAG); set VULTURE_ALLOW_DOWNGRADE=true to override"
        fi
    fi
    log "installing version: $VERSION"
}

# ─── 4. download_artifacts ─────────────────────────────────────────────────
download_artifacts() {
    if [ -n "${VULTURE_OFFLINE_TARBALL:-}" ]; then
        TARBALL=$VULTURE_OFFLINE_TARBALL
        SHASUM_FILE=${VULTURE_OFFLINE_TARBALL%.tar.gz}.SHA256SUMS
        SIG_FILE=${VULTURE_OFFLINE_TARBALL%.tar.gz}.sig
        log "using offline tarball: $TARBALL"
        return
    fi
    # Own temp dir for downloads; cleaned up by the EXIT trap (cleanup).
    # Named DL_TMP, not TMPDIR, so we don't clobber the standard env var
    # that mktemp/tar themselves consult.
    DL_TMP=$(mktemp -d)
    chmod 700 "$DL_TMP"
    TARBALL_NAME="vulture-${VERSION}-${OS}-${ARCH}.tar.gz"
    URL_BASE="${REPO_URL}/releases/download/${VERSION}"
    log "downloading $TARBALL_NAME"
    fetch "${URL_BASE}/${TARBALL_NAME}" "$DL_TMP/$TARBALL_NAME" \
        || err "tarball download failed"
    fetch "${URL_BASE}/SHA256SUMS" "$DL_TMP/SHA256SUMS" \
        || err "SHA256SUMS download failed"
    fetch "${URL_BASE}/SHA256SUMS.sig" "$DL_TMP/SHA256SUMS.sig" \
        2>/dev/null || warn "no cosign signature published"
    fetch "${URL_BASE}/SHA256SUMS.pem" "$DL_TMP/SHA256SUMS.pem" \
        2>/dev/null || true
    TARBALL=$DL_TMP/$TARBALL_NAME
    SHASUM_FILE=$DL_TMP/SHA256SUMS
    SIG_FILE=$DL_TMP/SHA256SUMS.sig
}

# ─── 5. verify_signature ──────────────────────────────────────────────────
verify_signature() {
    if ! command -v cosign >/dev/null 2>&1; then
        if [ "${VULTURE_ALLOW_UNSIGNED:-}" = "true" ]; then
            warn "cosign not on PATH; VULTURE_ALLOW_UNSIGNED=true; proceeding with SHA-only verification"
            return
        fi
        if [ "${VULTURE_REQUIRE_COSIGN:-}" = "true" ]; then
            err "cosign is required but not installed; install from https://github.com/sigstore/cosign"
        fi
        warn "cosign not on PATH; install for stronger supply-chain integrity (or set VULTURE_ALLOW_UNSIGNED=true to suppress)"
        warn "proceeding with SHA-only verification"
        return
    fi
    if [ ! -s "${SIG_FILE:-}" ]; then
        warn "no signature file present; SHA-only verification"
        return
    fi
    PEM="${SHASUM_FILE%/*}/SHA256SUMS.pem"
    if [ ! -s "$PEM" ]; then
        warn "no signing certificate present; SHA-only verification"
        return
    fi
    log "verifying release signature (cosign keyless + Rekor)"
    # verify-blob takes exactly ONE positional (the signed blob). The
    # signature and certificate come via flags. (Earlier revisions
    # passed the PEM as a stray positional, which broke verification.)
    cosign verify-blob \
        --certificate-identity-regexp "^https://github.com/${REPO_OWNER}/${REPO_NAME}/" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --certificate "$PEM" \
        --signature "$SIG_FILE" \
        "$SHASUM_FILE" \
        || err "cosign verification failed"
}

# ─── 6. verify_checksum ───────────────────────────────────────────────────
verify_checksum() {
    if command -v sha256sum >/dev/null 2>&1; then
        ( cd "$(dirname "$TARBALL")" && \
          grep " $(basename "$TARBALL")$" "$SHASUM_FILE" | sha256sum -c - ) \
        || err "SHA256 verification failed"
    elif command -v shasum >/dev/null 2>&1; then
        EXPECTED=$(grep " $(basename "$TARBALL")$" "$SHASUM_FILE" | awk '{print $1}')
        ACTUAL=$(shasum -a 256 "$TARBALL" | awk '{print $1}')
        [ "$EXPECTED" = "$ACTUAL" ] || err "SHA256 mismatch: $ACTUAL != $EXPECTED"
    else
        err "neither sha256sum nor shasum present; install one to proceed"
    fi
    log "SHA256 verified"
}

# ─── 7. extract_atomic (with TOCTOU re-validation) ────────────────────────
extract_atomic() {
    # Re-run the validation immediately before extraction (plan C4).
    REVALIDATED=$(resolve_path "$VULTURE_HOME")
    reject_if_system_dir "$REVALIDATED" \
        || err "VULTURE_HOME resolution changed since validate_home; aborting"
    NEW_HOME="${VULTURE_HOME}.new"
    rm -rf "$NEW_HOME"
    mkdir -p "$NEW_HOME"
    umask 077
    log "extracting tarball"
    # Single-pass tar -xzvf captures filelist for the quarantine
    # strip below (M3 — single read, no race window).
    tar -xzvf "$TARBALL" -C "$NEW_HOME" 2>"$NEW_HOME/.filelist" \
        >/dev/null || err "tar extraction failed"
    if [ -d "$VULTURE_HOME" ]; then
        OLD_HOME="${VULTURE_HOME}.old.$$"
        mv "$VULTURE_HOME" "$OLD_HOME"
    fi
    mv "$NEW_HOME" "$VULTURE_HOME"
    NEW_HOME=""   # consumed by the mv; nothing left to clean
    # NOTE: OLD_HOME is deliberately NOT deleted here. It is the rollback
    # point and is removed only by commit_install(), after the remaining
    # steps (deps, perms, symlink) succeed. If any of them fail, the EXIT
    # trap restores OLD_HOME instead of leaving a half-installed tree.
    log "extracted to $VULTURE_HOME"
}

# ─── 8. generate_jwt_secret ────────────────────────────────────────────────
generate_jwt_secret() {
    ENVFILE="$VULTURE_HOME/config/.env"
    if [ -f "$ENVFILE" ]; then
        log "preserving existing $ENVFILE"
        return
    fi
    mkdir -p "$VULTURE_HOME/config"
    chmod 700 "$VULTURE_HOME/config"
    if command -v openssl >/dev/null 2>&1; then
        SECRET=$(openssl rand -hex 32)
    else
        SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
    fi
    {
        printf 'VULTURE_JWT_SECRET=%s\n' "$SECRET"
        printf 'VULTURE_LOCAL_MODE=true\n'
        printf 'VULTURE_PORT=23000\n'
    } > "$ENVFILE"
    chmod 600 "$ENVFILE"
    log "generated JWT secret to $ENVFILE (0600)"
}

# ─── 9. install_python_deps ────────────────────────────────────────────────
# CLI-only builds (no bundled Python runtime) are a VALID install: the
# Go CLI + skill-based scanning work without the Python agents. Only
# LLM/agent-based scanning needs the agent runtime, which currently
# ships via Docker (Mode A/B). This function therefore distinguishes
# "CLI-only build" (success, with a clear note) from a genuinely broken
# dependency manifest (fail closed).
cli_only_note() {
    log ""
    log "  Note: this build does not bundle the Python agent runtime."
    log "  The CLI and skill-based scanning work as installed; LLM/agent-"
    log "  based scanning currently requires Docker (Mode A/B). See"
    log "  docs/guides/native_installation.md for current limitations."
    log ""
}

install_python_deps() {
    REQS="$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
    PIP="$VULTURE_HOME/runtime/python/bin/pip"
    # CLI-only build: no bundled interpreter and/or no dep manifest.
    if [ ! -x "$PIP" ] || [ ! -s "$REQS" ]; then
        cli_only_note
        return
    fi
    # A non-empty manifest MUST carry hashes — we install with
    # --require-hashes and will not silently weaken to a hashless install
    # in a supply-chain-sensitive path. Fail closed if the manifest has
    # ANY requirement line (first non-space char alphanumeric: covers
    # name==, name[extra]==, name>=, URLs, VCS pins) but no --hash=
    # anywhere. (A narrow `name==` check would miss extras/URLs and let a
    # hashless file slip through to an opaque pip --require-hashes error.)
    if ! grep -q -- '--hash=' "$REQS" \
       && grep -qE '^[[:space:]]*[A-Za-z0-9]' "$REQS"; then
        err "requirements-frozen.txt has dependencies but no hashes; refusing hashless install (rebuild the tarball with a pip-compile --generate-hashes lockfile)"
    fi
    INDEX=${VULTURE_PIP_INDEX_URL:-https://pypi.org/simple}
    # --trusted-host disables TLS certificate validation for a host, so we
    # add it ONLY for an explicit plaintext http:// mirror. For https (the
    # default and documented case) it must be omitted — otherwise it would
    # re-open a MITM hole on the very channel that pulls executable code.
    TRUSTED=""
    case "$INDEX" in
        http://*)
            HOST=$(printf '%s' "$INDEX" | sed -E 's|^http://||;s|/.*$||')
            warn "VULTURE_PIP_INDEX_URL is plaintext http://; disabling TLS verification for $HOST"
            TRUSTED="--trusted-host $HOST" ;;
    esac
    log "installing Python deps (this can take a few minutes)"
    # shellcheck disable=SC2086  # $TRUSTED is intentionally word-split
    # (empty, or the two tokens "--trusted-host <host>"); HOST is a bare
    # hostname with no spaces, so the split is safe.
    "$PIP" install --require-hashes --no-cache-dir --no-build-isolation \
        --disable-pip-version-check \
        --index-url "$INDEX" $TRUSTED \
        -r "$REQS" || err "pip install failed"
    log "Python deps installed"
}

# ─── 10. set_permissions ──────────────────────────────────────────────────
set_permissions() {
    chmod 700 "$VULTURE_HOME" \
              "$VULTURE_HOME/data" 2>/dev/null \
              "$VULTURE_HOME/config" 2>/dev/null || true
    [ -f "$VULTURE_HOME/config/.env" ] && chmod 600 "$VULTURE_HOME/config/.env"
    [ -f "$VULTURE_HOME/bin/vulture" ] && chmod 755 "$VULTURE_HOME/bin/vulture"
}

# ─── 11. link_binary ───────────────────────────────────────────────────────
link_binary() {
    LOCAL_BIN="$HOME/.local/bin"
    mkdir -p "$LOCAL_BIN"
    LINK="$LOCAL_BIN/vulture"
    if [ -e "$LINK" ] && [ ! -L "$LINK" ]; then
        warn "$LINK exists and is not a symlink; not overwriting"
    elif [ -L "$LINK" ]; then
        TARGET=$(readlink "$LINK")
        case "$TARGET" in
            "$VULTURE_HOME"/*) ln -sf "$VULTURE_HOME/bin/vulture" "$LINK" ;;
            *) warn "$LINK points outside VULTURE_HOME ($TARGET); not overwriting" ;;
        esac
    else
        ln -sf "$VULTURE_HOME/bin/vulture" "$LINK"
    fi
    case ":$PATH:" in
        *":$LOCAL_BIN:"*) ;;
        *) log "add this to your shell rc: export PATH=\"\$HOME/.local/bin:\$PATH\"" ;;
    esac
}

# ─── 12. strip_quarantine (darwin xattr strip; filelist cleanup all OSes) ─
strip_quarantine() {
    FILELIST="$VULTURE_HOME/.filelist"
    # macOS only: clear the com.apple.quarantine xattr on extracted files
    # (narrowed to the captured filelist, S7).
    if [ "$OS" = darwin ] && command -v xattr >/dev/null 2>&1 && [ -f "$FILELIST" ]; then
        while IFS= read -r entry; do
            # tar -xzvf line format: "x foo/bar/baz" or "foo/bar/baz"
            path=$(printf '%s' "$entry" | sed -E 's|^x[[:space:]]+||')
            full="$VULTURE_HOME/$path"
            [ -e "$full" ] && xattr -d com.apple.quarantine "$full" 2>/dev/null || true
        done < "$FILELIST"
    fi
    # Always remove the transient extraction filelist — on Linux the
    # darwin block is skipped, so clean up here unconditionally (M-fix:
    # previously left a stray .filelist in $VULTURE_HOME on Linux).
    rm -f "$FILELIST"
}

# ─── 12b. commit_install ───────────────────────────────────────────────────
# Mark the upgrade durable: delete the retained previous version and clear
# the rollback flag so the EXIT trap no longer reverts. Called only after
# every step that can fail (deps, perms, symlink) has succeeded.
commit_install() {
    if [ -n "${OLD_HOME:-}" ] && [ -d "$OLD_HOME" ]; then
        rm -rf "$OLD_HOME"
    fi
    OLD_HOME=""
    INSTALL_COMMITTED=1
}

# ─── 13. verify_install ───────────────────────────────────────────────────
verify_install() {
    if [ -x "$VULTURE_HOME/bin/vulture" ]; then
        "$VULTURE_HOME/bin/vulture" doctor --no-update-check >/dev/null 2>&1 \
            || warn "vulture doctor reports issues; run 'vulture doctor' to inspect"
    fi
}

# ─── 14. print_summary ────────────────────────────────────────────────────
print_summary() {
    log ""
    log "  Vulture $VERSION installed to $VULTURE_HOME"
    log ""
    log "  Try:"
    log "    vulture scan ./some-repo"
    log "    vulture start"
    log "    vulture stop"
    log ""
}

main() {
    # Roll back a half-applied upgrade and clean temp dirs on any exit.
    INSTALL_COMMITTED=0
    trap cleanup EXIT
    detect_platform
    validate_home
    resolve_version
    download_artifacts
    verify_signature
    verify_checksum
    extract_atomic
    generate_jwt_secret
    install_python_deps
    set_permissions
    link_binary
    strip_quarantine
    commit_install      # past here the swap is durable; trap won't revert
    verify_install
    print_summary
}

# Allow tests to source this file for per-function testing without
# running the installer. scripts/tests/test_install_sh.sh sets this.
if [ "${VULTURE_INSTALL_SOURCE_ONLY:-}" != "1" ]; then
    main "$@"
fi
