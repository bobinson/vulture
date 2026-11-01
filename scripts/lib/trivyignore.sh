#!/usr/bin/env sh
# scripts/lib/trivyignore.sh — the waiver-file check of the release CVE gate.
# SOURCE this file; do not execute it.
#
# trivyignore_check FILE TODAY — succeed when every line of FILE that is not
# blank and does not start with `#` is a waiver in the one form this repo
# accepts, a form Trivy honours:
#
#     <ID> exp:YYYY-MM-DD # <reason>
#
# single spaces, no tab, no leading whitespace, a real calendar date at most 90
# days after TODAY (YYYY-MM-DD, UTC), and a non-blank reason. Otherwise print
# "invalid ignore file FILE: <line number>: <why>" on stderr for each bad line
# and fail. TODAY is an argument rather than `date`, so tests can inject it;
# the day arithmetic is awk's, so no GNU date is needed. Trivy itself stops
# honouring an entry on its exp: date, which turns the gate red again.
# Callers: scripts/release-cve-gate.sh (tag time) and
# scripts/tests/test_release_cve_gate_wiring.sh (PR time).

trivyignore_check() {
    [ -f "$1" ] || { printf 'invalid ignore file %s: not a file\n' "$1" >&2; return 1; }
    awk -v f="$1" -v t="$2" '
        # leap(y) — 1 in a Gregorian leap year.
        function leap(y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 }
        # mdays(y, m) — the length of month m (1-12) of year y.
        function mdays(y, m) { return substr("312831303130313130313031", 2 * m - 1, 2) + (m == 2 && leap(y)) }
        # daynum(y, m, d) — a day count; only differences between two are used.
        function daynum(y, m, d) {
            if (m < 3) { y--; m += 12 }
            return 365 * y + int(y / 4) - int(y / 100) + int(y / 400) + int((153 * (m - 3) + 2) / 5) + d
        }
        # real(y, m, d) — 1 when y-m-d is a calendar date.
        function real(y, m, d) { return m >= 1 && m <= 12 && d >= 1 && d <= mdays(y, m) }
        # day(s) — daynum of a real YYYY-MM-DD date, -1 for anything else.
        function day(s,    y, m, d) {
            if (s !~ /^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$/) return -1
            y = substr(s, 1, 4) + 0; m = substr(s, 6, 2) + 0; d = substr(s, 9, 2) + 0
            return real(y, m, d) ? daynum(y, m, d) : -1
        }
        # shape(s) — why entry s is not `<ID> exp:<date> # <reason>`, or "".
        function shape(s) {
            if (index(s, "\t")) return "a tab; separate the fields with single spaces"
            if (s !~ /^[A-Za-z0-9][A-Za-z0-9._-]* exp:[^ ]+ # .*[^ ]/) return "want <ID> exp:YYYY-MM-DD # <reason>"
            return ""
        }
        # expiry(s) — why the exp: date of a well-shaped entry s is refused, or "".
        function expiry(s,    w, e, n) {
            split(s, w, " "); e = substr(w[2], 5); n = day(e)
            if (n < 0) return "exp: " e " is not a real date"
            if (n - today > 90) return "exp: " e " is more than 90 days after " t
            return ""
        }
        function why(s,    r) { r = shape(s); return r != "" ? r : expiry(s) }
        function refuse(n, r) { printf "invalid ignore file %s: %s: %s\n", f, n, r; bad = 1 }
        BEGIN { today = day(t); if (today < 0) { refuse(0, "today " t " is not a YYYY-MM-DD date"); exit } }
        /^[ \t]*$/ || /^#/ { next }
        { r = why($0); if (r != "") refuse(NR, r) }
        END { exit bad }
    ' "$1" >&2
}
