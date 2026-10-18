"""Every cap of the AST layer, in one table (feature 0102, D18, LLD §8.7).

Each operation's bound rests on one of these constants; the comment on each names the
§8.7 row (or the decision) whose bound it makes constant. None is read from the
environment (CLAUDE.md rule 6, D12): a cap an operator could raise is a cap an
adversarial repository could be planned around. No other ``shared.ast`` module binds a
cap of its own; they import it from here.

This module imports nothing: the isolated parse worker reads it (D2), so it must not pull
``shared.tools`` or anything else of the parent's machinery into that process.
"""

_KIB = 1024
_MIB = 1024 * _KIB

# ── §8.7 worker parse + captures ─────────────────────────────────────────────
MAX_FILE_SIZE = 512 * _KIB  # largest file shipped to a worker
MAX_NODES = 500_000  # descendant_count above it -> ir_too_large
MAX_DEPTH = 256  # too_deep; also guards_for's ancestor walk

# ── §8.7 frame decode + validate (D3) ────────────────────────────────────────
FRAME_CAP = 8 * _MIB  # largest frame either side reads
MAX_TEXT_BYTES = 128  # §6.2 validator: longest `text` value a model may carry

# ── §8.7 model queries ───────────────────────────────────────────────────────
MAX_CHAIN = 8  # chain_words: segments kept per chain (truncated, tallied)
MAX_WORDS = 16  # chain_words: words kept per identifier (tallied)
# words(): distinct identifiers memoised per process (an LRU). Measured on the bench tree:
# 7,439 distinct identifiers in 220,620 calls; at 4,096 entries the memo missed 17,847
# times, at 8,192 it misses only first sightings. About 1.7 MB when full.
WORDS_MEMO = 8_192

# ── §8.7 scope pass, origins, summaries ──────────────────────────────────────
MAX_BRANCH_DEPTH = 32  # scope pass per function: deeper branches -> unknown(depth)
MAX_ORIGINS = 16  # origins(node): larger sets collapse to reportable
MAX_SUMMARY_SIGNATURES = 4  # callee summary: runs per callee beyond the first
MAX_SUMMARY_DEPTH = 2  # callee summary: nesting -> unknown(summary_cap)

# ── §8.7 guards_for, candidates, hops ────────────────────────────────────────
MAX_ARG_NAMES = 16  # guards_for: argument names resolved per sink argument
MAX_TEST_NODES = 64  # guards_for: nodes read per guard TEST
GUARD_WINDOW = 8  # guards_for: preceding IF/TRY siblings examined
MAX_ARGS = 16  # candidates(family): arguments read per call (extra tallied)
MAX_HOPS = 8  # hops: hops kept per flow (then `truncated`)
MAX_HOP_SEGMENTS = 3  # hops: `.`-joined segments per hop name, else `<expr>` (A30 (2))

# ── §8.7 declines, coverage, breaker ─────────────────────────────────────────
# Decline ledger: per-rule bounded heap. The same fact as shared/tools/suppression.py's cap
# (D9), restated as a literal because importing that module would load shared.tools into the
# worker; test_0102_limits.py pins the two equal.
MAX_SUPPRESSIONS_PER_RULE = 50
MAX_FALLBACK_PATHS = 200  # coverage lists: the DISPLAY fallback_paths only (D24)
MAX_RENDERED_PATH = 200  # rendered path (safe_path, §10.3): the first characters kept (A30)
CIRCUIT_BREAK_AFTER = 20  # breaker: timeouts/crashes per audit before circuit_open

# ── D2 worker lifecycle and rlimits ──────────────────────────────────────────
WALL_TIMEOUT_S = 10  # wall-clock bound on one file's whole frame round trip
RECYCLE_AFTER = 2_000  # files one worker serves before it is replaced
WORKER_AS_BYTES = 256 * _MIB  # RLIMIT_AS of a worker (where enforceable)
WORKER_CPU_S = 30  # risk 14: cumulative RLIMIT_CPU (soft) of a worker (runaway backstop)
# Risk 14: RLIMIT_CPU's hard limit. Linux checks the hard limit first, so soft == hard would
# end the worker with SIGKILL; one second above the soft limit, SIGXCPU (the lifecycle exit
# the breaker does not count) arrives first. The worker may raise its soft limit by 1 s.
WORKER_CPU_HARD_S = WORKER_CPU_S + 1
# A5: measured 24.8 MB VmHWM (JS + Python grammars). It bounds no operation: it is the
# per-worker term of the bench's derived memory gate (§13.5),
# peak <= baseline + model_cache_budget + W x MAX_WORKER_RSS_MB + 16 MB.
MAX_WORKER_RSS_MB = 32  # a worker's resident bound, in MB

# ── §4 worker count, D5 model cache ──────────────────────────────────────────
WORKER_RESERVE = 192 * _MIB  # memory reserved per worker
MAX_WORKERS = 4  # upper clamp
MODEL_CACHE_CAP = 128 * _MIB  # model-cache byte budget ceiling
MODEL_CACHE_SHARE = 4  # the budget is at most 1/4 (25 %) of the deployment limit
