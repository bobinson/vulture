"""Smart file scanner that handles large repositories efficiently."""

import logging
import os
import re
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

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
    ".next", ".nuxt", ".output", ".svelte-kit", ".angular",
    ".docusaurus", "storybook-static",
    ".turbo", ".parcel-cache", ".cache", ".nyc_output",
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

# Generic extensions worth scanning that are not "source code" in the narrow
# sense. CODE_EXTENSIONS was chosen around compiled/interpreted languages, so
# everything else was skipped silently — a POST form with no CSRF token went
# unreported purely because it lived in a `.hbs` file, and documentation was
# never searched for credentials even though runbooks are a favourite place for
# them.
#
# NOTE: backup markers (`.bak`, `.old`, `.orig`, …) are deliberately absent.
# They are not file types — `effective_suffix()` resolves `notes.md.bak` to
# `.md`, so whitelisting `.md` covers the shadow copy too. Adding `.bak` here
# would be meaningless.
#
# Binary/asset extensions are also absent on purpose: scanning a PNG costs a
# read and can only produce noise.
WHITELIST_EXTENSIONS = frozenset({
    # Templates — form/markup rules (CSRF, XSS sinks) apply to these directly.
    ".html", ".htm", ".hbs", ".handlebars", ".pug", ".jade", ".ejs",
    ".mustache", ".twig", ".liquid", ".njk", ".vue", ".svelte", ".astro",
    # Docs / plain text — where hardcoded credentials and internal hostnames
    # habitually get pasted.
    ".md", ".markdown", ".rst", ".adoc", ".txt", ".csv", ".tsv",
    # Schema and infrastructure-as-code.
    ".sql", ".tf", ".tfvars", ".hcl", ".proto", ".graphql", ".gql",
    # Config dialects not already covered.
    ".properties", ".ini", ".cfg", ".conf", ".env", ".envrc",
    # Shells and build files beyond sh/bash.
    ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".mk", ".gradle",
    # Languages with no coverage before.
    ".lua", ".pl", ".pm", ".dart", ".groovy", ".clj", ".ex", ".exs", ".r",
})

# Canonical filenames that carry no extension. `.dockerfile` was already
# scanned while the far commoner `Dockerfile` was not — the rare spelling was
# covered and the standard one was not.
WELL_KNOWN_FILENAMES = frozenset({
    "Dockerfile", "Containerfile", "Makefile", "GNUmakefile", "Vagrantfile",
    "Jenkinsfile", "Procfile", "Rakefile", "Gemfile", "Brewfile", "Justfile",
    "CMakeLists.txt", ".npmrc", ".yarnrc", ".dockerignore", ".htaccess",
    ".netrc", ".pypirc", ".curlrc", ".gitconfig",
})


def _env_extensions(name: str) -> frozenset[str]:
    """Parse a comma-separated extension list from the environment.

    Accepts entries with or without a leading dot, in any case, with
    surrounding whitespace: ``".sol, jsonnet ,.CUE"``.
    """
    raw = os.getenv(name, "")
    out = set()
    for piece in raw.split(","):
        piece = piece.strip().lower()
        if not piece:
            continue
        out.add(piece if piece.startswith(".") else "." + piece)
    return frozenset(out)


def default_extensions() -> frozenset[str]:
    """Extensions scanned when a caller does not specify its own set.

    CODE_EXTENSIONS plus WHITELIST_EXTENSIONS plus anything in
    ``VULTURE_EXTRA_EXTENSIONS``. Set
    ``VULTURE_DISABLE_EXTENSION_WHITELIST=true`` to fall back to the narrow
    code-only set (rollback escape hatch).
    """
    if os.getenv("VULTURE_DISABLE_EXTENSION_WHITELIST", "").lower() == "true":
        return CODE_EXTENSIONS
    return CODE_EXTENSIONS | WHITELIST_EXTENSIONS | _env_extensions("VULTURE_EXTRA_EXTENSIONS")


# Suffixes / patterns for backup directories
_BACKUP_SUFFIXES = ("-backup", "_backup", "-old", "_old", "-bak", "_bak")

# ---------------------------------------------------------------------------
# Backup / shadow FILE awareness (feature 0068)
#
# A shadow copy such as `package.json.bak`, `server.ts~` or `config.yml.old`
# still contains source, and is frequently MORE dangerous than the live file
# (it preserves credentials and dependency pins that were later removed).
# Matching on Path.suffix alone resolved every one of these to `.bak`/`.old`,
# which is in no CODE_EXTENSION, so the scanner silently dropped them and no
# skill ever saw them. We therefore resolve the *effective* extension: the
# extension of whatever the file shadows.
# ---------------------------------------------------------------------------
_BACKUP_MARKERS = frozenset({
    "bak", "bak1", "backup", "bk", "old", "orig", "save", "saved", "copy",
    "tmp", "temp", "swp", "swo", "rej", "disabled", "unused", "deprecated",
    "prev", "previous",
})
# A trailing `~` (emacs/vi) is a marker on its own rather than a dot-suffix.
_BACKUP_TILDE = "~"


def _is_backup_marker(part: str) -> bool:
    """True if a dot-separated trailing token marks a shadow copy.

    Numeric rotations (`.1`, `.20240131`) count only as *additional* markers —
    handled by the caller — because a bare numeric suffix is ambiguous
    (`file.2` may be data), so it is stripped only alongside a real marker.
    """
    return part.lower() in _BACKUP_MARKERS


def strip_backup_markers(name: str) -> tuple[str, bool]:
    """Strip trailing shadow-copy markers, returning (base_name, was_backup).

    Handles stacking and numeric rotation: ``routes.ts.bak.1`` -> ``routes.ts``.
    """
    base = name
    found = False
    while True:
        if base.endswith(_BACKUP_TILDE) and len(base) > 1:
            base, found = base[:-1], True
            continue
        stem, dot, last = base.rpartition(".")
        if not dot:
            break
        if _is_backup_marker(last):
            base, found = stem, True
            continue
        # Numeric rotation is only meaningful directly after a real marker
        # (`.bak.1`); strip it and let the loop find the marker beneath.
        if last.isdigit():
            probe_stem, probe_dot, probe_last = stem.rpartition(".")
            if probe_dot and _is_backup_marker(probe_last):
                base, found = probe_stem, True
                continue
        break
    return base, found


def is_backup_name(name: str) -> bool:
    """True if ``name`` is a shadow/backup copy of another file."""
    return strip_backup_markers(name)[1]


def effective_suffix(name: str) -> str:
    """Extension of what this file *is*, seeing through backup markers.

    ``package.json.bak`` -> ``.json``; ``app.ts`` -> ``.ts``; ``notes.bak`` ->
    ``""`` (nothing underneath to recover).
    """
    base, _ = strip_backup_markers(name)
    return Path(base).suffix.lower()


def effective_name(name: str) -> str:
    """Filename with backup markers removed (``package.json.bak`` ->
    ``package.json``), so manifest//filename-keyed logic still matches."""
    return strip_backup_markers(name)[0]


# 500 silently truncated a 1274-file repo to 40% coverage and reported it as a
# complete scan (feature 0068). Real trees must fit; override per-scan with
# VULTURE_MAX_FILES.
MAX_FILES = _env_int("VULTURE_MAX_FILES", 50000)
MAX_FILE_SIZE = _env_int("VULTURE_MAX_FILE_SIZE", 512 * 1024)  # 512KB default

# Dependency manifests get a larger ceiling than source files. A lock file's
# size scales with the number of dependencies — i.e. with how much there is to
# find — so the general cap inverted the intent: juice-shop's
# ftp/package-lock.json.bak (750KB) was silently dropped, taking its
# known-vulnerable-component findings with it. Source files have no such
# property, so their cap is unchanged.
MAX_MANIFEST_SIZE = _env_int("VULTURE_MAX_MANIFEST_SIZE", 16 * 1024 * 1024)  # 16MB


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
    exts = extensions or default_extensions()
    # Canonical extensionless files (Dockerfile, Makefile, .npmrc) are folded
    # into the caller's extras so a skill gets them without opting in.
    extras = (extra_filenames or _EMPTY_EXTRAS) | WELL_KNOWN_FILENAMES
    # Part of the cache key: flipping VULTURE_SCAN_MINIFIED or the extension
    # whitelist must not return a stale walk from the opposite setting.
    return list(
        _scan_code_files_cached(source_path, exts, max_files, extras, _scan_minified())
    )


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
    scan_minified: bool = False,
) -> tuple[Path, ...]:
    """Cached inner scan — keyed by (path, extensions, max_files, extras,
    scan_minified).

    Returns an immutable tuple so callers cannot corrupt the cache.
    """
    root = Path(source_path)
    if not root.is_dir():
        return ()

    spec = _load_ignore_spec(str(root))
    files: list[Path] = []
    for p in _walk_filtered(root, root, spec):
        # Resolve backup/shadow copies to what they shadow, so `app.ts.bak`
        # matches `.ts` instead of the unmatchable `.bak` (feature 0068).
        eff_suffix = effective_suffix(p.name)
        eff_name = effective_name(p.name)
        # Minified/bundled vendor artefacts are not source. Checked on the
        # effective name so `app.min.js.bak` is excluded from content scanning
        # too — it is still enumerated by scan_backup_files() as an exposure.
        if not scan_minified and is_minified_name(eff_name):
            continue
        suffix_match = eff_suffix in exts and eff_name not in SKIP_FILES
        extras_match = bool(extras) and (
            _matches_extra(p.name, extras) or _matches_extra(eff_name, extras)
        )
        if not (suffix_match or extras_match):
            continue
        files.append(p)
        if len(files) >= max_files:
            # Truncation used to be silent, so a partial scan was indistinguishable
            # from a clean one. Make it loud (feature 0068).
            logger.warning(
                "scan_truncated path=%s files=%d max=%d — coverage is PARTIAL; "
                "raise VULTURE_MAX_FILES to scan the whole tree",
                source_path, len(files), max_files,
            )
            break
    logger.info("scan_complete path=%s files=%d max=%d", source_path, len(files), max_files)
    return tuple(files)


# Minified / bundled artefacts. One giant line of third-party code makes every
# line-oriented pattern fire at line 1 with no actionable fix — on juice-shop
# two vendored bundles produced 14 of 19 CWE-79 rows, burying the 5 real ones.
# Anchored on the dot/dash boundary so `minimist.js` and `bundle_helper.ts`
# are unaffected.
_MINIFIED_RE = re.compile(
    r"(?:[.-]min|\.bundle)\.(?:js|mjs|cjs|css)$", re.IGNORECASE
)


def is_minified_name(name: str) -> bool:
    """Return True when ``name`` looks like a minified or bundled artefact."""
    return bool(_MINIFIED_RE.search(name))


def _scan_minified() -> bool:
    """Whether minified bundles should be scanned anyway (opt-in)."""
    return os.getenv("VULTURE_SCAN_MINIFIED", "").lower() == "true"


def scan_backup_files(source_path: str, max_files: int = MAX_FILES) -> list[Path]:
    """Return every backup/shadow copy under ``source_path``.

    Deliberately independent of :func:`scan_code_files`' extension and
    SKIP_FILES gates. Marker stripping makes a shadow copy resolve to the type
    it shadows, which means it also inherits that type's *exclusions* —
    ``package-lock.json.bak`` resolves into SKIP_FILES and ``notes.md.bak``
    resolves to a non-code extension, so neither was ever yielded and neither
    could be reported as an exposure.

    Exposure is a property of the filename: a readable ``.bak`` in a served
    tree leaks its contents whether or not we would parse those contents.
    SKIP_DIRS and the ignore spec still apply, so vendored and ignored trees
    are excluded as usual.
    """
    return list(_scan_backup_files_cached(source_path, max_files))


@lru_cache(maxsize=16)
def _scan_backup_files_cached(source_path: str, max_files: int) -> tuple[Path, ...]:
    """Cached inner backup walk — keyed by (path, max_files)."""
    root = Path(source_path)
    if not root.is_dir():
        return ()

    spec = _load_ignore_spec(str(root))
    files: list[Path] = []
    for p in _walk_filtered(root, root, spec):
        if not is_backup_name(p.name):
            continue
        files.append(p)
        if len(files) >= max_files:
            logger.warning(
                "backup_scan_truncated path=%s files=%d max=%d — coverage is PARTIAL; "
                "raise VULTURE_MAX_FILES to enumerate every shadow copy",
                source_path, len(files), max_files,
            )
            break
    logger.info("backup_scan_complete path=%s files=%d", source_path, len(files))
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
    return name in _PATTERN_HELPER_BASENAMES
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
    if suffix == ".json" and (bool(parts_set & _LOCALE_DIRS) or _is_generated_json(name, parts_set)):
        return True
    return bool("skills" in parts_set and name.endswith("_check.py"))


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
