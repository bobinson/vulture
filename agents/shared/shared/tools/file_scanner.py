"""Smart file scanner that handles large repositories efficiently."""

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Iterator

# Shared line-classification patterns used across all skill files.
# Defined here once to satisfy DRY — import from this module.
SCANNER_DEF_LINE = re.compile(r"re\.compile\(|=\s*\[?\s*re\.", re.IGNORECASE)
SAFE_IMPORT_LINE = re.compile(r"^\s*(?:from|import)\s")
COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")

logger = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    """Read an integer from environment with fallback to default."""
    val = os.environ.get(name)
    if val is None:
        return default
    try:
        return max(1, int(val))
    except ValueError:
        return default

# Directories to always skip
SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", ".bzr",
    "node_modules", "__pycache__", ".tox", ".nox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "vendor", "third_party", "dist", "build",
    ".next", ".nuxt", ".output",
    "venv", ".venv", "env", ".env",
    ".idea", ".vscode", ".eclipse", ".claude",
    "target", "bin", "obj",
    "coverage", ".coverage", "htmlcov",
    ".terraform", ".pulumi",
    "data", "fixtures", "testdata", "test-fixtures",
    "snapshots", "mocks", "__snapshots__",
    "playwright-report", "test-results",
})

# File names to always skip (lock files, generated files)
SKIP_FILES = frozenset({
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "Pipfile.lock", "poetry.lock", "go.sum", "Cargo.lock",
    "composer.lock", "Gemfile.lock", "shrinkwrap.json",
    ".DS_Store", "Thumbs.db",
})

# Code file extensions we care about
CODE_EXTENSIONS = frozenset({
    ".py", ".pyw", ".go", ".js", ".ts", ".jsx", ".tsx",
    ".mjs", ".cjs", ".mts", ".cts",
    ".java", ".rs", ".rb", ".erb", ".php", ".phtml", ".cs", ".cpp",
    ".c", ".h", ".m", ".mm", ".swift", ".kt", ".scala",
    ".yaml", ".yml", ".toml", ".json", ".xml",
    ".sh", ".bash", ".dockerfile",
})

# Suffixes / patterns for backup directories
_BACKUP_SUFFIXES = ("-backup", "_backup", "-old", "_old", "-bak", "_bak")

MAX_FILES = _env_int("VULTURE_MAX_FILES", 500)
MAX_FILE_SIZE = _env_int("VULTURE_MAX_FILE_SIZE", 512 * 1024)  # 512KB default


def scan_code_files(
    source_path: str,
    extensions: frozenset[str] | None = None,
    max_files: int = MAX_FILES,
    extra_filenames: frozenset[str] | None = None,
) -> list[Path]:
    """Scan a directory for code files efficiently.

    Skips common non-code directories, respects file limits,
    and only returns files with relevant extensions.

    Results are cached by (source_path, extensions, max_files,
    extra_filenames) so that multiple skills scanning the same directory
    reuse the walk result.

    Args:
        source_path: Root directory to scan.
        extensions: File extensions to include. Defaults to CODE_EXTENSIONS.
        max_files: Maximum number of files to return.
        extra_filenames: Optional explicit basenames (or basename
            prefixes ending in ``.``) to include in addition to
            ``extensions``. Use this for files whose suffix doesn't
            classify them — e.g. ``.env``, ``.envrc``, ``.env.production``
            all match an entry of ``".env"`` (literal or as prefix).

    Returns:
        List of Path objects for code files found.
    """
    exts = extensions or CODE_EXTENSIONS
    extras = extra_filenames or _EMPTY_EXTRAS
    return list(_scan_code_files_cached(source_path, exts, max_files, extras))


_EMPTY_EXTRAS: frozenset[str] = frozenset()


def _matches_extra(name: str, extras: frozenset[str]) -> bool:
    """True if ``name`` is exactly an extras entry, OR starts with one
    of them used as a prefix (so ``.env`` matches ``.env.production``)."""
    if name in extras:
        return True
    for e in extras:
        # Treat entries ending in '.' OR plain '.env'-style names as a
        # prefix family, so `.env.production` matches an extras entry of
        # `.env`. Don't accept arbitrary substrings.
        if name.startswith(e + "."):
            return True
    return False


@lru_cache(maxsize=16)
def _scan_code_files_cached(
    source_path: str, exts: frozenset[str], max_files: int, extras: frozenset[str],
) -> tuple[Path, ...]:
    """Cached inner scan — keyed by (path, extensions, max_files, extras).

    Returns an immutable tuple so callers cannot corrupt the cache.
    """
    root = Path(source_path)
    if not root.is_dir():
        return ()

    spec = _load_ignore_spec(str(root))
    files: list[Path] = []
    for p in _walk_filtered(root, root, spec):
        suffix_match = p.suffix.lower() in exts and p.name not in SKIP_FILES
        extras_match = bool(extras) and _matches_extra(p.name, extras)
        if not (suffix_match or extras_match):
            continue
        files.append(p)
        if len(files) >= max_files:
            break
    logger.info("scan_complete path=%s files=%d max=%d", source_path, len(files), max_files)
    return tuple(files)


@lru_cache(maxsize=16)
def _load_ignore_spec(source_path: str):
    """Load gitignore-style patterns from `.vultureignore` and
    `.gitignore` at ``source_path`` and compile a ``PathSpec``.

    Honors `.gitignore` by default (set ``VULTURE_IGNORE_GITIGNORE=true``
    to disable). Honors `.vultureignore` always when present.

    Returns a compiled ``pathspec.PathSpec`` or ``None`` if both files
    are absent / unreadable / pathspec isn't installed.
    """
    try:
        import pathspec
    except ImportError:
        return None

    root = Path(source_path)
    patterns: list[str] = []

    # Read .gitignore first so .vultureignore patterns layer on top
    # (later patterns override earlier ones in pathspec's gitwildmatch
    # semantics). Skip if operator opted out.
    if os.environ.get("VULTURE_IGNORE_GITIGNORE", "").lower() != "true":
        gi = root / ".gitignore"
        if gi.is_file():
            try:
                patterns.extend(gi.read_text(encoding="utf-8", errors="ignore").splitlines())
            except OSError:
                pass

    vi = root / ".vultureignore"
    if vi.is_file():
        try:
            patterns.extend(vi.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            pass

    if not patterns:
        return None
    # Use the newer "gitignore" style introduced in pathspec 0.12; the
    # legacy "gitwildmatch" name was deprecated in pathspec 1.x. Fall
    # back to gitwildmatch for pathspec < 0.12 (which doesn't expose
    # gitignore) so we don't break older installs.
    try:
        return pathspec.PathSpec.from_lines("gitignore", patterns)
    except (ValueError, LookupError):
        return pathspec.PathSpec.from_lines("gitwildmatch", patterns)


def _walk_filtered(root: Path, scan_root: Path, spec) -> Iterator[Path]:
    """Walk directory tree, skipping ignored directories.

    Skips entries that:
    - Are in :data:`SKIP_DIRS` or :data:`SKIP_FILES` (hardcoded baseline).
    - Match a `.vultureignore` / `.gitignore` pattern from ``scan_root``.
    - Are symlinks (avoid loops).
    - Are backup directories (`-backup`, `_old`, etc.).
    """
    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        return

    dirs: list[Path] = []
    for entry in entries:
        if entry.is_symlink():
            continue
        if _is_path_ignored(entry, scan_root, spec):
            continue
        if entry.is_file():
            yield entry
        elif entry.is_dir() and entry.name not in SKIP_DIRS and not _is_backup_dir(entry.name):
            dirs.append(entry)

    for d in dirs:
        yield from _walk_filtered(d, scan_root, spec)


def _is_path_ignored(entry: Path, scan_root: Path, spec) -> bool:
    """True if ``entry`` matches the loaded ignore spec.

    Pathspec's gitwildmatch matcher operates on POSIX-style relative
    paths. Directories must be matched with a trailing slash for
    dir-only patterns (e.g. `node_modules/`) to apply.
    """
    if spec is None:
        return False
    try:
        rel = entry.relative_to(scan_root)
    except ValueError:
        return False
    rel_posix = rel.as_posix()
    if entry.is_dir():
        rel_posix += "/"
    return spec.match_file(rel_posix)


def read_file_safe(path: Path, max_size: int = MAX_FILE_SIZE) -> str | None:
    """Read a file safely with size limit and in-process caching.

    Args:
        path: File path to read.
        max_size: Maximum file size in bytes.

    Returns:
        File content as string, or None if unreadable/too large.
    """
    return _read_file_cached(str(path), max_size)


@lru_cache(maxsize=1024)
def _read_file_cached(path_str: str, max_size: int) -> str | None:
    """Cached file reader keyed by path string (hashable)."""
    try:
        p = Path(path_str)
        if p.stat().st_size > max_size:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


@lru_cache(maxsize=1024)
def _splitlines_cached(path_str: str, max_size: int) -> tuple[str, ...]:
    """Cached splitlines — avoids re-splitting the same file across skills."""
    content = _read_file_cached(path_str, max_size)
    if content is None:
        return ()
    return tuple(content.splitlines())


def read_file_lines(path: Path, max_size: int = MAX_FILE_SIZE) -> tuple[str, ...] | None:
    """Read a file and return its lines, with caching.

    Uses the same file cache as read_file_safe but also caches the
    splitlines() result so multiple skills analyzing the same file
    avoid redundant list creation.

    Returns a tuple (immutable) to avoid copying the cached result.

    Args:
        path: File path to read.
        max_size: Maximum file size in bytes.

    Returns:
        Tuple of lines, or None if unreadable/too large.
    """
    result = _splitlines_cached(str(path), max_size)
    if not result and _read_file_cached(str(path), max_size) is None:
        return None
    return result


_TEST_SUFFIXES = frozenset({
    ".test.ts", ".test.tsx", ".test.js", ".test.jsx",
    ".spec.ts", ".spec.tsx", ".spec.js", ".spec.jsx",
})
_TEST_DIRS = frozenset({"e2e", "tests", "__tests__", "test-utils"})


def is_test_file(path: Path) -> bool:
    """Check if a file is a test file.

    Args:
        path: File path to check.

    Returns:
        True if the path looks like a test file.
    """
    return _is_test_file_cached(str(path), path.name.lower(), path.stem.lower())


@lru_cache(maxsize=2048)
def _is_test_file_cached(path_str: str, name: str, stem: str) -> bool:
    """Cached test-file classification keyed on path string."""
    if stem.startswith("test_") or stem.endswith("_test"):
        return True
    if name.startswith("jest."):
        return True
    if any(name.endswith(sfx) for sfx in _TEST_SUFFIXES):
        return True
    stem_parts = set(stem.replace("_", "-").split("-"))
    if "test" in stem_parts or "tests" in stem_parts:
        return True
    parts_lower = {p.lower() for p in Path(path_str).parts}
    return bool(parts_lower & _TEST_DIRS)


_LOCALE_DIRS = frozenset({"locales", "i18n", "translations", "messages"})
_DATA_DIRS = frozenset({"data", "fixtures", "testdata"})

# Directories whose files describe DETECTION patterns rather than
# contain vulnerable code. Findings here are almost certainly meta-
# detection FPs (a CORS-detector regex matches its own regex literal).
# Self-scan 2026-05-26 attributed ~60% of FPs to this class.
_SKILL_SOURCE_DIRS = frozenset({"skills", "validate"})
# Specific file basenames inside agents/shared/shared/tools/ that are
# helper-pattern dictionaries — not vulnerable code.
_PATTERN_HELPER_BASENAMES = frozenset({
    "obfuscation.py",
    "_var_reference.py",
    "pattern_matcher.py",
})


def is_skill_source_file(path: Path) -> bool:
    """Return True for files that DESCRIBE detection patterns rather
    than contain vulnerable code. Skill files contain regex strings
    that match their own patterns (CWE-78 detector includes the literal
    `os.system(` in its source), so scanning them produces meta-detection
    FPs.

    Caught categories:
      - `agents/<X>/<X>_agent/skills/...` — every detector lives here
      - `agents/shared/shared/validate/...` — context_heuristics et al
      - `agents/shared/shared/tools/{obfuscation,_var_reference,...}.py`
    """
    return _is_skill_source_file_cached(str(path), path.name)


@lru_cache(maxsize=2048)
def _is_skill_source_file_cached(path_str: str, name: str) -> bool:
    parts_lower = {p.lower() for p in Path(path_str).parts}
    if parts_lower & _SKILL_SOURCE_DIRS:
        return True
    if name in _PATTERN_HELPER_BASENAMES:
        return True
    return False
_GENERATED_JSON_KEYWORDS = ("catalog", "_data", "fixture", "snapshot")


def _is_generated_json(name: str, parts_set: set[str]) -> bool:
    """Check if a JSON file is generated/non-source (catalog, config, data)."""
    if any(kw in name for kw in _GENERATED_JSON_KEYWORDS):
        return True
    if name.startswith("tsconfig") or name == "package.json":
        return True
    return bool(parts_set & _DATA_DIRS)


def is_generated_file(path: Path) -> bool:
    """Check if a file is generated / non-source (lock, locale, data, config).

    Args:
        path: File path to check.

    Returns:
        True if the file is auto-generated or non-source-code.
    """
    return _is_generated_file_cached(str(path), path.name.lower(), path.suffix.lower())


@lru_cache(maxsize=2048)
def _is_generated_file_cached(path_str: str, name: str, suffix: str) -> bool:
    """Cached generated-file classification keyed on path string."""
    if name in SKIP_FILES:
        return True
    parts_set = {p.lower() for p in Path(path_str).parts}
    if suffix == ".json":
        if bool(parts_set & _LOCALE_DIRS) or _is_generated_json(name, parts_set):
            return True
    if "skills" in parts_set and name.endswith("_check.py"):
        return True
    return False


def _is_backup_dir(name: str) -> bool:
    """Check if directory name looks like a backup."""
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in _BACKUP_SUFFIXES)


# Entry point / config file detection for LLM file prioritization.
_ENTRY_POINT_NAMES = frozenset({
    "main.py", "app.py", "index.ts", "index.js", "index.tsx", "index.jsx",
    "server.py", "server.ts", "server.js", "config.py", "config.ts",
    "config.js", "settings.py", "manage.py", "wsgi.py", "asgi.py",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "main.go", "main.rs", "main.java", "Program.cs",
})

_ENTRY_POINT_STEMS = frozenset({
    "main", "app", "index", "server", "config", "settings",
    "manage", "wsgi", "asgi",
})

# Handler-family stem TOKENS — matched per-token after splitting the stem on
# `_ - .` — so non-standard entry points the exact name/stem lists miss are
# still caught (user_handler.py, auth_controller.rb, api_routes.go,
# lambda_function.py, user_resolver.py). Token (not substring) matching keeps
# "rapid" from hitting on "api". Deliberately EXCLUDES main/app/index (those
# stay exact-stem only) so test_main.py / main_helper.py are NOT entry points.
_ENTRY_POINT_STEM_TOKENS = frozenset({
    "handler", "handlers", "route", "routes", "router",
    "controller", "controllers", "endpoint", "endpoints",
    "webhook", "webhooks", "middleware", "resolver", "resolvers",
    "lambda", "view", "views", "urls", "api", "serializer", "serializers",
})

# Directory names whose contents are entry points regardless of filename —
# Go `cmd/`, Rails/Express `routes/`+`controllers/`, Next.js `app/api`+`pages/api`
# style `api/`, serverless `functions/`, etc. Kept focused (no app/src/pages)
# so the Tier-2 set doesn't balloon.
_ENTRY_POINT_DIRS = frozenset({
    "cmd", "api", "routes", "controllers", "handlers", "endpoints",
    "functions", "webhooks", "resolvers", "middleware", "views",
})


def clear_caches() -> None:
    """Clear all LRU caches for file scanning.

    Call at the start of each audit run to ensure stale file contents from
    a previous run don't leak into the current analysis.

    Derived caches are cleared first so they don't hold stale references
    to source caches that are about to be invalidated.
    """
    _is_test_file_cached.cache_clear()
    _is_generated_file_cached.cache_clear()
    _splitlines_cached.cache_clear()
    _read_file_cached.cache_clear()
    _scan_code_files_cached.cache_clear()


def is_entry_or_config(path: Path) -> bool:
    """Check if a file is an entry point or configuration file.

    Used to PRIORITIZE files for the LLM phase (Tier 2), not to filter them.
    Matches in order: exact filename, exact stem, a handler-family stem token
    (handler/route/controller/...), or residence under an entry-point directory
    (cmd/, routes/, api/, ...). The last two catch non-standard handlers like
    `cmd/api/handler.go`, `routes/users.rb`, or `app/api/users/route.ts` that
    the exact name/stem lists miss.

    Args:
        path: File path to check.

    Returns:
        True if the file looks like an entry point or config file.
    """
    if path.name in _ENTRY_POINT_NAMES:
        return True
    stem = path.stem.lower()
    if stem in _ENTRY_POINT_STEMS:
        return True
    # Non-standard handlers: any stem TOKEN is a handler-family keyword.
    tokens = stem.replace("-", "_").replace(".", "_").split("_")
    if any(tok in _ENTRY_POINT_STEM_TOKENS for tok in tokens):
        return True
    # ...or the file lives under an entry-point directory. Check parent
    # components only (path.parts[:-1]) — never the filename itself.
    return any(part.lower() in _ENTRY_POINT_DIRS for part in path.parts[:-1])
