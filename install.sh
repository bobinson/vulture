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
#   VULTURE_PIP_INDEX_URL   Alternate PyPI mirror (must be https://)
#   VULTURE_NO_UPDATE_CHECK Disable doctor's GH-API call after install
#   VULTURE_ALLOW_DOWNGRADE  Allow VULTURE_VERSION older than fallback
#
# This script is shellcheck-clean and POSIX-sh (no bashisms).

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

# resolve_path PATH — canonicalise symlinks where possible; echo the result.
resolve_path() {
    if command -v readlink >/dev/null 2>&1; then
        readlink -f "$1" 2>/dev/null || printf '%s' "$1"
    else
        printf '%s' "$1"
    fi
}

# reject_if_system_dir PATH — err() if PATH is a system directory or a child of
# one. /root is rejected only as an exact target (so /root/.vulture is allowed).
reject_if_system_dir() {
    _p=$1
    case "$_p" in
        /|/bin|/sbin|/lib|/lib64|/boot|/sys|/proc|/dev|/root|/etc|/usr|/var)
            err "refusing system directory: $_p" ;;
        /bin/*|/sbin/*|/lib/*|/lib64/*|/boot/*|/sys/*|/proc/*|/dev/*|/etc/*|/usr/*|/var/*)
            err "refusing system directory: $_p" ;;
    esac
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
    reject_if_system_dir "$RESOLVED"
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
        VERSION=$(curl -fsSL "$RELEASES_API" 2>/dev/null \
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
    DOWNLOAD_DIR=$(mktemp -d)
    chmod 700 "$DOWNLOAD_DIR"
    TARBALL_NAME="vulture-${VERSION}-${OS}-${ARCH}.tar.gz"
    URL_BASE="${REPO_URL}/releases/download/${VERSION}"
    log "downloading $TARBALL_NAME"
    fetch "$DOWNLOAD_DIR/$TARBALL_NAME" "${URL_BASE}/${TARBALL_NAME}" \
        || err "tarball download failed"
    fetch "$DOWNLOAD_DIR/SHA256SUMS" "${URL_BASE}/SHA256SUMS" \
        || err "SHA256SUMS download failed"
    fetch "$DOWNLOAD_DIR/SHA256SUMS.sig" "${URL_BASE}/SHA256SUMS.sig" \
        2>/dev/null || warn "no cosign signature published"
    fetch "$DOWNLOAD_DIR/SHA256SUMS.pem" "${URL_BASE}/SHA256SUMS.pem" \
        2>/dev/null || true
    TARBALL=$DOWNLOAD_DIR/$TARBALL_NAME
    SHASUM_FILE=$DOWNLOAD_DIR/SHA256SUMS
    SIG_FILE=$DOWNLOAD_DIR/SHA256SUMS.sig
}

# fetch DEST URL — download URL to DEST with a timeout and bounded retries.
fetch() {
    _dest=$1
    _url=$2
    curl -fsSL --connect-timeout 30 --max-time 300 --retry 3 --retry-delay 2 \
        -o "$_dest" "$_url"
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
        warn "no certificate published; SHA-only verification"
        return
    fi
    log "verifying release signature (cosign + Rekor)"
    cosign verify-blob \
        --certificate-identity-regexp "^https://github.com/${REPO_OWNER}/${REPO_NAME}/" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        --rekor-url https://rekor.sigstore.dev \
        --certificate "$PEM" \
        --signature "$SIG_FILE" \
        "$SHASUM_FILE" || err "cosign verification failed"
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
    reject_if_system_dir "$REVALIDATED"
    NEW_HOME="${VULTURE_HOME}.new"
    rm -rf "$NEW_HOME"
    mkdir -p "$NEW_HOME"
    umask 077
    log "extracting tarball"
    # Single-pass tar -xzvf captures filelist for the quarantine
    # strip below (M3 — single read, no race window).
    tar -xzvf "$TARBALL" -C "$NEW_HOME" 2>"$NEW_HOME/.filelist" \
        >/dev/null || err "tar extraction failed"
    # Retain the previous install as OLD_HOME until commit_install (H2):
    # a crash before commit is rolled back by the EXIT trap.
    if [ -d "$VULTURE_HOME" ]; then
        OLD_HOME="${VULTURE_HOME}.old.$$"
        mv "$VULTURE_HOME" "$OLD_HOME"
    fi
    mv "$NEW_HOME" "$VULTURE_HOME"
    log "extracted to $VULTURE_HOME"
}

# ─── commit_install (H2) ──────────────────────────────────────────────────
# Final commit point: the new install is good, so drop the retained previous
# install and mark the upgrade committed (the trap no longer rolls back).
commit_install() {
    if [ -n "${OLD_HOME:-}" ] && [ -d "$OLD_HOME" ]; then
        rm -rf "$OLD_HOME"
    fi
    COMMITTED=1
    INSTALL_COMMITTED=1
}

# ─── cleanup (H2 EXIT trap) ───────────────────────────────────────────────
# On an uncommitted abort, restore OLD_HOME -> VULTURE_HOME. Always remove
# leftover temp/staging dirs.
cleanup() {
    if [ "${COMMITTED:-}" != "1" ] && [ "${INSTALL_COMMITTED:-}" != "1" ] \
       && [ -n "${OLD_HOME:-}" ] && [ -d "$OLD_HOME" ]; then
        rm -rf "$VULTURE_HOME"
        mv "$OLD_HOME" "$VULTURE_HOME"
    fi
    [ -n "${NEW_HOME:-}" ] && rm -rf "$NEW_HOME"
    [ -n "${DOWNLOAD_DIR:-}" ] && rm -rf "$DOWNLOAD_DIR"
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
cli_only_note() {
    log "agent runtime not bundled in this build — 'vulture scan' with"
    log "LLM/agents requires Docker mode (Mode A/B); the CLI + skills still work."
}

install_python_deps() {
    PIP="$VULTURE_HOME/runtime/python/bin/pip"
    REQS="$VULTURE_HOME/runtime/agents/requirements-frozen.txt"
    # CLI-only build: no bundled interpreter, or no/empty frozen manifest.
    if [ ! -x "$PIP" ] || [ ! -s "$REQS" ]; then
        cli_only_note
        return 0
    fi
    # Fail-closed hashless detection: any requirement line (non-blank,
    # non-comment, non-continuation) when the file has no --hash= lines.
    if ! grep -q -- '--hash=' "$REQS"; then
        # Confirm there is at least one real requirement line to install.
        if grep -Eq '^[[:space:]]*[^#[:space:]]' "$REQS"; then
            err "requirements-frozen.txt has no --hash= lines; refusing hashless install (fail-closed)"
        fi
        cli_only_note
        return 0
    fi
    INDEX=${VULTURE_PIP_INDEX_URL:-https://pypi.org/simple}
    log "installing Python deps (this can take a few minutes)"
    # Only disable TLS verification (--trusted-host) for an explicit http://
    # mirror; never for the default/https index.
    case "$INDEX" in
        http://*)
            HOST=$(printf '%s' "$INDEX" | sed -E 's|^http://||;s|/.*$||')
            warn "VULTURE_PIP_INDEX_URL is http:// ($INDEX); disabling TLS verification for $HOST"
            "$PIP" install --require-hashes --no-cache-dir --no-build-isolation \
                --disable-pip-version-check \
                --index-url "$INDEX" --trusted-host "$HOST" \
                -r "$REQS" || err "pip install failed"
            ;;
        *)
            "$PIP" install --require-hashes --no-cache-dir --no-build-isolation \
                --disable-pip-version-check \
                --index-url "$INDEX" \
                -r "$REQS" || err "pip install failed"
            ;;
    esac
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

# ─── 12. strip_quarantine (darwin only, narrowed to extracted files) ─────
strip_quarantine() {
    # Strip macOS quarantine xattrs using the extraction filelist (darwin only).
    if [ "$OS" = darwin ] && command -v xattr >/dev/null 2>&1 \
       && [ -f "$VULTURE_HOME/.filelist" ]; then
        while IFS= read -r entry; do
            # tar -xzvf line format: "x foo/bar/baz" or "foo/bar/baz"
            path=$(printf '%s' "$entry" | sed -E 's|^x[[:space:]]+||')
            full="$VULTURE_HOME/$path"
            [ -e "$full" ] && xattr -d com.apple.quarantine "$full" 2>/dev/null || true
        done < "$VULTURE_HOME/.filelist"
    fi
    # Remove the temp filelist on ALL platforms (A3).
    rm -f "$VULTURE_HOME/.filelist"
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
    # Fail fast / no unset vars during a real install (kept out of top level so
    # sourcing for tests does not inherit it).
    set -eu
    # Install the EXIT trap here (not at top level) so sourcing for tests does
    # not hijack the harness's own trap.
    trap cleanup EXIT INT TERM
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
    commit_install
    verify_install
    print_summary
}

# Testability seam: when sourced with VULTURE_INSTALL_SOURCE_ONLY=1, expose the
# functions for unit tests without running the installer.
if [ "${VULTURE_INSTALL_SOURCE_ONLY:-}" != "1" ]; then
    main "$@"
fi
