# shellcheck shell=sh
#
# scripts/lib/runtime_strip.sh — keep the bundled python-build-standalone (PBS)
# runtime permissive-only. SOURCE this (like scripts/lib/hash.sh); it defines
# functions and has no side effects of its own.
#
# Why this exists
# ---------------
# PBS's `_dbm` extension (CPython's `dbm.ndbm`) links a copyleft ndbm backend:
#   - macOS builds  -> GNU gdbm  (GPL-3.0)   [verified 2026-06-24]
#   - Linux builds  -> Berkeley DB 6.0.19 (Sleepycat; permissive but inconsistent)
# Nothing in Vulture uses `dbm.ndbm`; `dbm.open()` falls back to the pure-Python
# `dbm.dumb`, so removing `_dbm` is functionally inert. Stripping it makes every
# platform's tarball permissive-only AND uniform. `assert_no_copyleft_native` is
# the build-time regression guard that fails the build if copyleft native code
# ever sneaks back in (e.g. a future PBS bump).

# _runtime_dynload <runtime_python_dir> — echo the interpreter's lib-dynload dir
# (version-agnostic: works for python3.12, 3.13, …). Empty if not a PBS runtime.
_runtime_dynload() {
    find "$1/lib" -type d -name lib-dynload 2>/dev/null | head -n1
}

# strip_copyleft_modules <runtime_python_dir> — remove the copyleft-linked `_dbm`
# extension from the bundled interpreter. Idempotent; a no-op when absent (e.g. a
# lean / non-bundled stage).
strip_copyleft_modules() {
    _dl=$(_runtime_dynload "$1")
    [ -n "$_dl" ] || return 0
    rm -f "$_dl"/_dbm.*.so
    return 0
}

# assert_no_copyleft_native <runtime_python_dir> — fail (non-zero) if any bundled
# native extension still carries copyleft (GPL/AGPL) code. Scoped to lib-dynload
# (where optional native modules like `_dbm` live); broad dependency-license
# scanning is the release SBOM/CVE pipeline's job. `-a` makes grep match inside
# the (binary) .so files; works with both GNU and BSD grep.
assert_no_copyleft_native() {
    _dl=$(_runtime_dynload "$1")
    [ -n "$_dl" ] || return 0
    _hits=$(grep -rla -e 'GNU gdbm' -e 'GNU Affero General Public' "$_dl" 2>/dev/null || true)
    if [ -n "$_hits" ]; then
        echo "error: copyleft (GPL/AGPL) native code in the bundled runtime:" >&2
        printf '  %s\n' "$_hits" >&2
        return 1
    fi
    return 0
}
