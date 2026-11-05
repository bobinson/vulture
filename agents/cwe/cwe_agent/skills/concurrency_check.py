"""Concurrency vulnerability detection skill."""

import re
from pathlib import Path

from agents import function_tool

from cwe_agent.catalog import enrich_finding
from cwe_agent.skills._lexical import stripped_code
from shared.tools.file_scanner import (
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import collect_scoped_body, extract_snippet

# CWE-362: Race condition (shared mutable state without locks)
SHARED_STATE_PATTERNS = [
    # Tightened: bound by [^)]* so a `.*` doesn't backtrack across long
    # arg lists, and require `target=` to be a real kwarg (preceded by
    # comma/paren) — not a mention in a string literal anywhere on the
    # line.
    re.compile(r"(?:threading\.Thread|Thread)\s*\([^)]*?[\s,(]target\s*="),
    re.compile(r"go\s+\w+\s*\("),  # Go goroutine
]

# Lock-acquire shapes: actual `.acquire()`, `.lock()`, `Lock()`,
# `with mutex:`, etc. Distinct from a mere mention of the word "Lock"
# in an import or a comment — we use this to detect actual SYNCHRONIZED
# blocks that protect a region of code.
LOCK_ACQUIRE_PRESENT = re.compile(
    r"(?:"
    r"\b(?:threading|asyncio)\.Lock\s*\(|"
    r"\bsync\.(?:Mutex|RWMutex)\b|"
    r"\.(?:Lock|RLock|acquire)\s*\(|"
    r"\bsynchronized\s*\(|"
    r"\bwith\s+\w+(?:_lock|Lock|_mutex|Mutex)\b"
    r")"
)
GLOBAL_VAR_WRITE = re.compile(r"^\s*(?:global|var)\s+\w+")

# CWE-367: TOCTOU (time-of-check time-of-use)
TOCTOU_CHECK_PATTERNS = [
    re.compile(r"os\.path\.exists\s*\("),
    re.compile(r"os\.path\.isfile\s*\("),
    re.compile(r"os\.access\s*\("),
    re.compile(r"os\.Stat\s*\("),  # Go
    re.compile(r"File\.exists\?\s*\("),  # Ruby
]
TOCTOU_USE_PATTERNS = [
    re.compile(r"\bopen\s*\("),
    re.compile(r"os\.(?:Open|Create|Remove|Rename)\s*\("),
    re.compile(r"os\.(?:remove|rename|unlink|mkdir)\s*\("),
    re.compile(r"shutil\.\w+\s*\("),
]

# CWE-833: Deadlock (nested lock acquisition)
LOCK_ACQUIRE = [
    re.compile(r"\.(?:acquire|Lock|RLock)\s*\("),
    re.compile(r"\.(?:lock|Lock)\(\)"),  # Go mutex
    re.compile(r"synchronized\s*\("),  # Java
]

# CWE-662: Improper synchronization
THREAD_NO_SYNC = [
    re.compile(r"threading\.Thread\s*\("),
    re.compile(r"go\s+func\s*\("),
]
_GO_FUNC = THREAD_NO_SYNC[1]
# Synchronisation a goroutine shows in its OWN body without a lock, read on code
# with strings and comments stripped (`"<-"` in a message is not a channel
# operation): a channel send or receive (a send happens before the matching
# receive completes), the builtin `close(ch)`, or `Done`/`Wait` on a receiver the
# file declares as a `sync.WaitGroup` (a variable, field or parameter of that
# type, or one bound to `sync.WaitGroup{}`, `&sync.WaitGroup{}` or
# `new(sync.WaitGroup)`). Any other `Wait` or `Done` (`cmd.Wait()`,
# `ctx.Done()`) orders nothing.
_CHANNEL_SYNC = re.compile(r"<-|(?<![\w.])close\s*\(")
_WAIT_GROUP_CALL = re.compile(r"(?<![\w$])([A-Za-z_]\w{0,63})\s{0,4}\.\s{0,4}(?:Done|Wait)\s{0,4}\(")
_WAIT_GROUP_DECL = re.compile(
    r"(?<![\w.])([A-Za-z_]\w{0,63})\s{1,8}\*?sync\.WaitGroup\b"
    r"|(?<![\w.])([A-Za-z_]\w{0,63})\s{0,8}:?=\s{0,8}"
    r"(?:&\s{0,4}sync\.WaitGroup\s{0,4}\{|sync\.WaitGroup\s{0,4}\{|new\(\s{0,4}sync\.WaitGroup\s{0,4}\))"
)
_GOROUTINE_BODY_LINES = 40

IMPORT_LINE = re.compile(r"^\s*(?:import|from|package)\s+")


def _should_skip(file_path: Path) -> bool:
    """True for files whose shared-state patterns cannot be real races.

    ``is_prose_file`` is the third arm: prose has no threads, so an
    unsynchronised snippet quoted in a design note is a mention, not a race.
    """
    return is_generated_file(file_path) or is_test_file(file_path) or is_prose_file(file_path)


def check_concurrency(source_path: str) -> dict:
    """Check for concurrency vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of concurrency issues.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if _should_skip(file_path):
            continue
        _analyze_file(file_path, findings)

    return {"findings": findings}


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for concurrency issues."""
    lines = read_file_lines(file_path)
    if lines is None:
        return

    # Per-thread-spawn lock detection. Previously we asked "does this
    # file mention the word Lock anywhere?" and skipped EVERY no-sync
    # finding when the answer was yes. That's wrong — importing a lock
    # library or having an unrelated lock in a different function still
    # leaves THIS thread spawn unsynchronised.
    #
    # Heuristic: a thread spawn is considered "potentially synchronised"
    # only when an actual lock-acquire shape appears within ±20 lines of
    # the spawn site. This favors precision (fewer false positives on
    # real lock usage) while still catching the common antipattern of
    # spawning concurrent work with no nearby synchronisation primitive.

    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _check_toctou(file_path, line, line_num, lines, findings)
        _check_thread_no_sync(file_path, line, line_num, lines, findings)
        _check_deadlock(file_path, line, line_num, lines, findings)


def _check_toctou(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for TOCTOU race conditions (CWE-367).

    Suppress the finding when the check+use pair is wrapped in an EAFP
    `try/except` block — the standard Python idiom is to skip the
    pre-check entirely and handle the error from the operation, but
    the equally valid `if exists: ... ; except FileNotFoundError`
    pattern is safe and shouldn't be flagged.
    """
    is_check = any(p.search(line) for p in TOCTOU_CHECK_PATTERNS)
    if not is_check:
        return
    # Look for file use within next 5 lines
    window_end = min(line_num + 5, len(lines))
    window = "\n".join(lines[line_num:window_end])
    has_use = any(p.search(window) for p in TOCTOU_USE_PATTERNS)
    if not has_use:
        return
    # EAFP guard: scan ±5 lines around the check for try/except wrapping
    # that handles the relevant errors, in which case the operation is
    # atomic-from-the-caller's-perspective and the pattern is safe.
    eafp_start = max(0, line_num - 6)
    eafp_end = min(len(lines), line_num + 5)
    eafp_window = "\n".join(lines[eafp_start:eafp_end])
    if _EAFP_TRY_BLOCK.search(eafp_window):
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.concurrency.toctou",
        "category": "CWE-367",
        "title": "Time-of-check time-of-use (TOCTOU) race condition",
        "description": f"File existence check at line {line_num} followed by file operation",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use atomic operations or handle errors from the operation directly",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "367"))


# EAFP guard: try block wrapping the check that catches a file-related
# error means the apparent TOCTOU is an explicit recovery path, not a
# race vulnerability.
_EAFP_TRY_BLOCK = re.compile(
    r"\btry\s*:[\s\S]{0,400}?except\b[^\n]*\b"
    r"(?:FileNotFoundError|IsADirectoryError|NotADirectoryError|PermissionError|OSError|IOError|FileExistsError)"
)


def _check_thread_no_sync(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for threading without synchronisation (CWE-662).

    Locks are checked WITHIN the surrounding function scope (±20 lines)
    rather than file-globally. A lock_acquire elsewhere in the file
    doesn't protect this specific spawn site; conversely, a lock right
    next to the spawn does. A goroutine needs no lock when its own body
    communicates over a channel or signals a WaitGroup.
    """
    if not any(p.search(line) for p in THREAD_NO_SYNC) or _synchronised(line, line_num, lines):
        return
    finding = {
        "severity": "high",
        "check_id": "cwe.concurrency.no_sync",
        "category": "CWE-662",
        "title": "Thread/goroutine without synchronization",
        "description": f"Concurrent execution at line {line_num} with no nearby locking primitive",
        "file_path": str(file_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": "Use mutexes, locks, or channels to synchronize shared state",
    }
    finding["code_snippet"] = extract_snippet(lines, line_num)
    findings.append(enrich_finding(finding, "662"))


def _synchronised(line: str, line_num: int, lines: list[str]) -> bool:
    """A lock-acquire shape within +/-20 lines, or synchronisation in the goroutine's body."""
    scope = "\n".join(lines[max(0, line_num - 21):line_num + 20])
    locked = bool(LOCK_ACQUIRE_PRESENT.search(scope))
    return locked or _goroutine_synchronised(line, line_num, lines)


def _goroutine_synchronised(line: str, line_num: int, lines: list[str]) -> bool:
    """True when the goroutine started on ``line`` synchronises inside its own body.

    The body is the rest of the spawn line (a one-line goroutine) and the block
    the spawn opens; a channel operation outside it orders none of its writes.
    """
    spawn = _GO_FUNC.search(line)
    if spawn is None:
        return False
    block = collect_scoped_body(lines, line_num, True, _GOROUTINE_BODY_LINES, _GOROUTINE_BODY_LINES)
    body = [stripped_code(text) for text in (line[spawn.end():], *block)]
    return any(map(_CHANNEL_SYNC.search, body)) or _signals_wait_group(body, lines)


def _signals_wait_group(body: list[str], lines: list[str]) -> bool:
    """True when ``body`` calls `Done`/`Wait` on a WaitGroup the file declares."""
    receivers = {m.group(1) for code in body for m in _WAIT_GROUP_CALL.finditer(code)}
    return bool(receivers) and not receivers.isdisjoint(_wait_groups(lines))


def _wait_groups(lines: list[str]) -> set[str]:
    """The names the file declares as a `sync.WaitGroup`."""
    text = "\n".join(stripped_code(t) for t in lines if "WaitGroup" in t)
    return {"".join(names) for names in _WAIT_GROUP_DECL.findall(text)}  # one group is empty


def _check_deadlock(
    file_path: Path,
    line: str,
    line_num: int,
    lines: list[str],
    findings: list[dict],
) -> None:
    """Check for potential deadlock via nested lock acquisition (CWE-833)."""
    is_lock = any(p.search(line) for p in LOCK_ACQUIRE)
    if not is_lock:
        return
    # Look for another lock acquisition within next 10 lines
    window_end = min(line_num + 10, len(lines))
    for i in range(line_num, window_end):
        if any(p.search(lines[i]) for p in LOCK_ACQUIRE):
            finding = {
                "severity": "high",
                "check_id": "cwe.concurrency.deadlock",
                "category": "CWE-833",
                "title": "Potential deadlock from nested lock acquisition",
                "description": f"Multiple lock acquisitions detected near line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Ensure consistent lock ordering or use a single lock to prevent deadlocks",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "833"))
            return


check_concurrency_tool = function_tool(check_concurrency)
