"""CWE-548 — Exposure of information through directory listing.

Structural signature (no tainted source): an *explicitly-enabled* directory
listing — ``serveIndex(``, ``autoIndex: true``, Apache ``Options +Indexes``,
``directoryListing: true``, or ``dotfiles: 'allow'``. A matching disable
directive within the window suppresses.

NOTE: Go's ``http.FileServer(`` is deliberately NOT a sink. It is the idiomatic,
non-vulnerable way nearly every Go service serves static files; flagging it
unconditionally was a near-guaranteed false positive (0057 review) since serving
files != intentionally exposing a directory index, and ``require_source=False``
gives no way to distinguish intent. Only the explicit-enable forms carry signal.

Bounded quantifiers (ReDoS-safe).
"""

import re

from cwe_agent.skills.signatures.schema import CweSignature

DIRLIST_SINK = re.compile(
    r"serveIndex\s*\(|autoIndex\s*[:=]\s*true|"
    r"Options\s+[^\n]{0,40}\+?Indexes\b|directoryListing\s*[:=]\s*true|"
    r"dotfiles\s*:\s*['\"]allow|"
    r"list_directory|directory\s*=\s*True",
    re.IGNORECASE,
)
DIRLIST_SANITIZER = re.compile(
    r"autoIndex\s*[:=]\s*false|Options\s+[^\n]{0,40}-Indexes\b|"
    r"directoryListing\s*[:=]\s*false|dotfiles\s*:\s*['\"]deny|"
    r"index\s*:\s*false",
    re.IGNORECASE,
)

SIGNATURES = (
    CweSignature(
        cwe_id="548",
        sig_id="cwe.sig.dirlist",
        title="Directory listing enabled: information exposure",
        severity="medium",
        languages=("JavaScript", "TypeScript", "Java", "Python"),
        sink=DIRLIST_SINK,
        sanitizer=DIRLIST_SANITIZER,
        require_source=False,
        confidence=0.55,
        status="trusted",
    ),
)
