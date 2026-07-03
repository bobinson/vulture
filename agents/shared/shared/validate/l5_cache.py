"""L5 verdict cache — file-backed SQLite store.

Caches LLM verdicts keyed by
    sha256(file_path:line_start:line_end:check_id:model_name)
so re-scans of unchanged code skip the LLM call entirely
(feature 0046 §H, addresses audit issue #9).

Storage: a single SQLite file at `~/.vulture/l5_cache.db` (or wherever
`VULTURE_L5_CACHE_PATH` points). Concurrent agent processes are
safe via SQLite's own WAL-mode locking — we don't try to hold long
transactions.

NOT a replacement for the DB-backed `audit_memories.l5_verdict_cache`
column (migration 019); that column is reserved for the cross-
deployment cache (Phase 2). v1 uses this local SQLite to unblock the
single-machine repeat-audit case.

TTL: 30 days. Older entries are pruned lazily on read.
"""

from __future__ import annotations

import hashlib
import logging
import os
import sqlite3
import threading
import time
from typing import Optional

log = logging.getLogger(__name__)

_TTL_S = 30 * 24 * 3600          # 30 days
_LOCK = threading.Lock()
_CONN: Optional[sqlite3.Connection] = None
_DB_PATH: Optional[str] = None
_DISABLED = False


def _default_path() -> str:
    base = os.environ.get("VULTURE_L5_CACHE_PATH", "")
    if base:
        return base
    home = os.environ.get("VULTURE_DATA_DIR", "")
    if not home:
        home = os.path.join(os.path.expanduser("~"), ".vulture")
    return os.path.join(home, "l5_cache.db")


def _connect() -> Optional[sqlite3.Connection]:
    """Lazy, thread-safe connection accessor. Returns None on
    initialisation failure — callers should silently skip caching."""
    global _CONN, _DB_PATH, _DISABLED
    if _DISABLED:
        return None
    if _CONN is not None:
        return _CONN
    with _LOCK:
        if _CONN is not None:
            return _CONN
        if _DISABLED:
            return None
        try:
            path = _default_path()
            parent = os.path.dirname(path) or "."
            os.makedirs(parent, exist_ok=True)
            # A-9: ensure the cache directory + file are owner-only. The
            # cache stores verdicts that could be poisoned across users
            # if world-writable. We do NOT enforce ownership — that's
            # an OS / packaging concern — but we do ensure mode 0700/0600
            # the first time we create them.
            try:
                os.chmod(parent, 0o700)
            except OSError:
                pass
            existed = os.path.exists(path)
            conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
            if not existed:
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS l5_cache (
                    cache_key   TEXT PRIMARY KEY,
                    exploitable REAL NOT NULL,
                    reasoning   TEXT NOT NULL,
                    model       TEXT NOT NULL,
                    language    TEXT NOT NULL,
                    judged_at   REAL NOT NULL
                )
            """)
            _CONN = conn
            _DB_PATH = path
            log.info("[validate.l5] cache initialised at %s", path)
            return conn
        except Exception as exc:  # noqa: BLE001
            log.warning("[validate.l5] cache init failed (continuing without): %s", exc)
            _DISABLED = True
            return None


def cache_key(*, file_path: str, line_start: int, line_end: int,
              check_id: str, model: str, file_sig: str = "") -> str:
    """Stable key shared by reader + writer. SHA-256 → 32 hex chars.

    `file_sig` is a short hash of the file's contents (audit A-1) — when
    the file changes, cache entries for it become unreachable rather
    than serving stale verdicts for shifted line ranges.
    """
    raw = f"{file_path}:{line_start}:{line_end}:{check_id}:{model}:{file_sig}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def lookup(key: str) -> Optional[dict]:
    """Return `{exploitable, reasoning, model, language, judged_at}` or
    None on miss / expired / disabled."""
    conn = _connect()
    if conn is None:
        return None
    try:
        # Serialize access to the shared connection. The L5 pool judges
        # batches concurrently (ThreadPoolExecutor); two threads calling
        # execute() on one sqlite3 connection raise SQLITE_MISUSE ("bad
        # parameter or other API misuse") or tear a cursor read, silently
        # dropping the lookup. _connect()'s fast path doesn't hold _LOCK once
        # initialised, so taking it here cannot deadlock.
        with _LOCK:
            row = conn.execute(
                "SELECT exploitable, reasoning, model, language, judged_at "
                "FROM l5_cache WHERE cache_key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        judged_at = float(row[4])
        if time.time() - judged_at > _TTL_S:
            return None
        return {
            "exploitable": float(row[0]),
            "reasoning": row[1] or "",
            "model": row[2] or "",
            "language": row[3] or "",
            "judged_at": judged_at,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("[validate.l5] cache lookup failed: %s", exc)
        return None


def store(key: str, *, exploitable: float, reasoning: str,
          model: str, language: str) -> None:
    """Best-effort write. Silent on failure (caching is a perf nicety,
    not a correctness requirement)."""
    conn = _connect()
    if conn is None:
        return
    try:
        # Serialize writes to the shared connection (see lookup()).
        with _LOCK:
            conn.execute(
                "INSERT OR REPLACE INTO l5_cache "
                "(cache_key, exploitable, reasoning, model, language, judged_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (key, float(exploitable), reasoning, model, language, time.time()),
            )
    except Exception as exc:  # noqa: BLE001
        log.warning("[validate.l5] cache store failed: %s", exc)


def stats() -> dict:
    """Lightweight info for telemetry / startup probe."""
    conn = _connect()
    if conn is None:
        return {"enabled": False, "path": _default_path()}
    try:
        with _LOCK:
            row = conn.execute("SELECT COUNT(*) FROM l5_cache").fetchone()
        return {"enabled": True, "path": _DB_PATH or "", "rows": int(row[0])}
    except Exception:  # noqa: BLE001
        return {"enabled": False, "path": _DB_PATH or ""}
