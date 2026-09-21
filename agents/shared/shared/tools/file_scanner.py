"""Smart file scanner that handles large repositories efficiently."""

import fnmatch
import logging
import os
import re
import threading
from collections.abc import Iterable, Iterator
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
    ".java", ".rs", ".rb", ".rake", ".erb", ".php", ".phtml", ".cs", ".cpp",
    # `.cc`/`.cxx`/`.hpp` are ordinary C++ spellings and `.kts` an ordinary
    # Kotlin one; without them a C++ project that writes `.cc` was invisible to
    # EVERY agent, not only to CWE-778. Feature 0087 step 9 names the first
    # three explicitly.
    ".cc", ".cxx", ".hpp", ".hh", ".hxx", ".kts",
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
    # PR9/PR10: template and config dialects that skills ALREADY carry patterns
    # for. Without these the corresponding rule arms are dead code — measured:
    # JSP arms in input validation, Jinja arms in three skills, and ASP.NET
    # arms in two could never fire because the extension was never scanned.
    # A declared language must be reachable or the declaration is a lie.
    ".j2", ".jinja", ".jinja2", ".jsp", ".jspx", ".config", ".csproj",
})

# Canonical filenames that carry no extension. `.dockerfile` was already
# scanned while the far commoner `Dockerfile` was not — the rare spelling was
# covered and the standard one was not.
WELL_KNOWN_FILENAMES = frozenset({
    "Dockerfile", "Containerfile", "Makefile", "GNUmakefile", "Vagrantfile",
    "Jenkinsfile", "Procfile", "Rakefile", "Gemfile", "Brewfile", "Justfile",
    "CMakeLists.txt", ".npmrc", ".yarnrc", ".dockerignore", ".htaccess",
    ".netrc", ".pypirc", ".curlrc", ".gitconfig",
    # Extensionless, and carries privilege-escalation configuration.
    "sudoers",
})


# Feature 0091 §9 — root-relative paths that can EXECUTE when a project is
# merely OPENED, before anybody runs anything.
#
# THE DEFECT. `.vscode`, `.idea` and `.claude` are all in :data:`SKIP_DIRS`, so
# a scan of a project root never descended into them and the single most
# dangerous thing a repository can carry — a VS Code task with
# ``"runOn": "folderOpen"`` that shells out the moment the folder is opened —
# was invisible to every skill. The one time it WAS reported it came from the
# LLM tier of a scan rooted at `.vscode` itself, and the next scan's
# prior-findings block suppressed it, its absence was read as repair, and the
# lineage row closed while the line sat in the file byte for byte.
#
# THE RULE. The walker yields exactly these paths out of an otherwise-pruned
# directory. Everything else in that directory stays pruned AND stays reported
# through :func:`pruned_dirs`, at the granularity that is actually pruned — the
# container itself is NOT reported, because it WAS walked and a blanket prefix
# would put the file we just read out of scope, which would make the finding
# uncloseable forever (feature 0091 §6.5 / S15).
#
# Patterns are root-relative, ``/``-separated, and matched segment by segment,
# so ``*`` never crosses a directory boundary.
# ``cwe_agent.skills.workspace_autorun_check`` IMPORTS this set rather than
# restating it: one list, and one anti-drift test that every entry here is
# matched by at least one of the skill's rules.
WELL_KNOWN_AUTORUN_FILES: frozenset[str] = frozenset({
    ".vscode/tasks.json",
    ".vscode/launch.json",
    ".vscode/settings.json",
    ".idea/runConfigurations/*.xml",
    ".idea/workspace.xml",
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks/*",
    ".devcontainer/devcontainer.json",
    ".devcontainer/*.sh",
})


def _ancestor_prefixes(patterns: Iterable[str]) -> frozenset[str]:
    """Every directory prefix that must be entered to reach ``patterns``."""
    out: set[str] = set()
    for pattern in patterns:
        parts = pattern.split("/")
        for i in range(1, len(parts)):
            out.add("/".join(parts[:i]))
    return frozenset(out)


# `.vscode`, `.idea`, `.idea/runConfigurations`, `.claude`, `.claude/hooks`,
# `.devcontainer` — derived, never restated, so a new pattern above cannot be
# unreachable because somebody forgot to un-prune its parent.
_AUTORUN_DIR_PREFIXES: frozenset[str] = _ancestor_prefixes(WELL_KNOWN_AUTORUN_FILES)


def match_rel_pattern(rel_path: str, pattern: str) -> bool:
    """Segment-wise fnmatch: ``*`` matches within one segment, never across.

    Public because :mod:`cwe_agent.skills.workspace_autorun_check` decides which
    of its rules owns a walked file with the SAME matcher the walker used to
    yield it. Two matchers would be two definitions of the allowlist.
    """
    parts = rel_path.split("/")
    pattern_parts = pattern.split("/")
    if len(parts) != len(pattern_parts):
        return False
    return all(fnmatch.fnmatchcase(a, b) for a, b in zip(parts, pattern_parts))


def is_autorun_path(rel_path: str) -> bool:
    """True when a root-relative path is a known editor/IDE autorun FILE."""
    return any(match_rel_pattern(rel_path, pat) for pat in WELL_KNOWN_AUTORUN_FILES)


# The deepest pattern in the allowlist, in segments. Bounds how far
# :func:`is_autorun_entry` may climb above a scan root looking for the segments
# that identify a file, so the climb is decided by the allowlist rather than by
# a number someone has to keep in step with it.
_AUTORUN_MAX_DEPTH: int = max(len(p.split("/")) for p in WELL_KNOWN_AUTORUN_FILES)


def autorun_rel_path(scan_root: Path, entry: Path) -> str:
    """``entry`` as the path the autorun allowlist recognises, or ``""``.

    An autorun file is identified by segments the scan root can CONSUME. The
    patterns are rooted at the repository (``.vscode/tasks.json``), so pointing
    a scan at ``.vscode`` itself leaves the relative path ``tasks.json`` — the
    identifying segment is gone and the file stops being recognised. Measured:
    a rescan of ``…/blu-simulator/.vscode`` returned 0 findings with the
    malicious ``tasks.json`` on disk, and absence closed the row.

    So the root-relative path is tried first, then the same path re-anchored at
    each ancestor of the scan root, up to the deepest pattern in the allowlist.
    The MATCHING path is returned rather than a bool because the walker and the
    skill must agree on more than membership: the skill picks which rule owns
    the file from this same string, and a rule chosen from an unanchored path
    is no rule at all — the file is read and reported on by nobody.

    Climbing cannot widen what counts as an autorun file: every candidate is
    matched against the same patterns, and a file whose real path never spells
    one out still matches nothing.
    """
    rel = _rel_of(scan_root, entry)
    if not rel:
        return ""
    if is_autorun_path(rel):
        return rel
    ancestor = scan_root
    for _ in range(_AUTORUN_MAX_DEPTH - 1):
        if ancestor.parent == ancestor:  # reached the filesystem root
            break
        ancestor = ancestor.parent
        candidate = _rel_of(ancestor, entry)
        if candidate and is_autorun_path(candidate):
            return candidate
    return ""


def is_autorun_entry(scan_root: Path, entry: Path) -> bool:
    """True when ``entry`` is an autorun file, however deep the scan root sits."""
    return autorun_rel_path(scan_root, entry) != ""


def _is_autorun_dir(rel_path: str) -> bool:
    """True when a root-relative DIRECTORY must be entered to reach one."""
    return any(match_rel_pattern(rel_path, pat) for pat in _AUTORUN_DIR_PREFIXES)


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


# ── LLM prompt feed (feature 0075) ───────────────────────────────────────────
# The extension set the LLM PROMPT sees, as distinct from what the scanner walks.
# It lives here, beside CODE_EXTENSIONS / WHITELIST_EXTENSIONS / default_extensions(),
# so a reader asking "what does the model see?" finds the answer where the scanner's
# own sets are — and so a future third feed path inherits it instead of rediscovering
# it. Two feed paths already diverged once by each naming their own set.

# Prose/data types subtracted from the PROMPT by default. Not a claim that prose holds
# no defects — a README can leak a credential, which is why the skill tier keeps
# scanning it. A BUDGET argument: the prompt has a fixed character ceiling and doc text
# displaces the source the model was asked to analyse.
LLM_PROSE_EXTENSIONS: frozenset[str] = frozenset({
    ".md", ".markdown", ".rst", ".txt", ".adoc", ".csv", ".tsv",
})

# SHIPS EMPTY, deliberately. An earlier revision excluded `.graphql`/`.gql` citing
# "0 true positives of 32 adjudicated". That evidence was CONFOUNDED with the defect
# 0075 fixes: no skill carries GraphQL patterns, so all 32 rows had zero skill findings
# and were therefore all in the RAW/unnumbered bucket, whose precision was 12.5% with
# 78% mislocation. "0 of 32" cannot be separated from "all 32 presented blind".
# Re-adjudicated under the numbered regime, 2 of 11 are real — a cleartext wallet
# privateKey selection and an unbounded full-table fetch — so excluding them would have
# deleted both. The mechanism stays for operators who cannot send config dialects to a
# third-party provider.
LLM_INELIGIBLE_EXTENSIONS: frozenset[str] = frozenset()


def _llm_feed_prose() -> bool:
    """Whether prose/data files reach the LLM prompt. Default False (budget)."""
    return os.getenv("VULTURE_LLM_FEED_PROSE", "").strip().lower() in (
        "1", "true", "yes", "on")


def _llm_ineligible_extensions() -> frozenset[str]:
    raw = os.getenv("VULTURE_LLM_INELIGIBLE_EXTENSIONS")
    if raw is None:
        return LLM_INELIGIBLE_EXTENSIONS
    return frozenset(
        e.strip().lower() if e.strip().startswith(".") else "." + e.strip().lower()
        for e in raw.split(",") if e.strip()
    )


def _llm_feed_unified() -> bool:
    """Whether both LLM feed paths resolve ONE extension set. Default True.

    Feature 0075 T2.8, a one-release escape hatch for the RC3 fix. `false` restores
    the original asymmetry deliberately: the single-shot path back to the narrow
    code-only set, the batched sweep back to the wide default with no `extensions=`
    at all. That pair IS the defect — two paths feeding one model disagreeing about
    what counts as code — which is why unified is the default and this exists only to
    unblock an operator, not as a supported configuration.
    """
    return os.getenv("VULTURE_LLM_FEED_UNIFY", "true").strip().lower() not in (
        "0", "false", "no", "off")


def llm_feed_extensions(single_shot: bool = True) -> frozenset[str] | None:
    """Extensions fed to the LLM phase: the scan set, minus prompt-only subtractions.

    Subtractive by design. Narrowing to a hand-picked allowlist silently drops file
    types nobody has measured — an earlier revision narrowed to CODE_EXTENSIONS and
    lost `.sql`, `.tf` and `.yml`, taking three adjudicated-real findings with them.
    Delegating to ``default_extensions()`` also keeps ``VULTURE_EXTRA_EXTENSIONS`` and
    the ``VULTURE_DISABLE_EXTENSION_WHITELIST`` hatch working for the feed.

    Returns a ``frozenset``: ``scan_code_files`` folds this into an ``lru_cache`` key,
    and a mutable ``set`` raises ``TypeError: unhashable type``.
    """
    if not _llm_feed_unified():
        # Pre-0075 behaviour, reproduced exactly: narrow set for the single-shot
        # path, None (the wide default) for the sweep. Returning None is the point —
        # the sweep's original call passed no `extensions=` at all.
        return CODE_EXTENSIONS if single_shot else None
    excluded = _llm_ineligible_extensions()
    if not _llm_feed_prose():
        excluded = excluded | LLM_PROSE_EXTENSIONS
    return frozenset(default_extensions()) - excluded


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
# find — so a single cap inverted the intent: the manifests most worth scanning
# were exactly the ones large enough to be dropped, taking their
# known-vulnerable-component findings with them. Source files have no such
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
        _scan_code_files_cached(
            source_path, exts, max_files, extras, _scan_minified(),
        )
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


def _matches_extras_any(name: str, eff_name: str, extras: frozenset[str]) -> bool:
    """True if either the literal or the backup-stripped name is in ``extras``."""
    if not extras:
        return False
    return _matches_extra(name, extras) or _matches_extra(eff_name, extras)


def _wanted_by_name(
    name: str, eff_suffix: str, eff_name: str,
    exts: frozenset[str], extras: frozenset[str],
) -> bool:
    """Name/extension gate for one walked path (no I/O)."""
    if eff_suffix in exts and eff_name not in SKIP_FILES:
        return True
    return _matches_extras_any(name, eff_name, extras)


def _include_file(
    path: Path, exts: frozenset[str], extras: frozenset[str], scan_minified: bool,
) -> bool:
    """Decide whether one walked path belongs in the scan set.

    Backup/shadow copies are resolved to what they shadow first, so `app.ts.bak`
    matches `.ts` instead of the unmatchable `.bak` (feature 0068), and
    `app.min.js.bak` is recognised as minified — it is still enumerated by
    scan_backup_files() as an exposure.

    The name gate runs before the minified gates because it is free: the content
    heuristic costs a (cached) read, so it is only paid for files that would
    otherwise be scanned.
    """
    eff_name = effective_name(path.name)
    if not _wanted_by_name(path.name, effective_suffix(path.name), eff_name, exts, extras):
        return False
    if scan_minified:
        return True
    return not (is_minified_name(eff_name) or is_minified_content(path))


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
        if not _include_file(p, exts, extras, scan_minified):
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
# line-oriented pattern fire at line 1 with no actionable fix, and a handful of
# vendored bundles can easily out-number the real findings in a category —
# burying signal in code the project does not control. Anchored on the dot/dash
# boundary so `minimist.js` and `bundle_helper.ts` are unaffected.
_MINIFIED_RE = re.compile(
    r"(?:[.-]min|\.bundle)\.(?:js|mjs|cjs|css)$", re.IGNORECASE
)


def is_minified_name(name: str) -> bool:
    """Return True when ``name`` looks like a minified or bundled artefact."""
    return bool(_MINIFIED_RE.search(name))


# The name regex only recognises the old `.min` / `.bundle` convention. Modern
# bundlers emit chunks whose name is nothing but a content hash
# (`index-eq0Dxw.js`, `613-32d22f8f.js`, `page.js`), so a whole build directory
# slips past a name-only rule. Those files are still recognisable by SHAPE:
# generated code is packed onto a few enormous lines.
#
# Threshold: 2000 chars. The signature detector already treats 600 chars on one
# line as pathological for a hand-written line; 2000 is >3x that, and across
# ~6.2k JS/CSS-family files in five real trees NO hand-written file had a single
# line above it, while every generated bundle had lines of 3k-130k chars.
_MINIFIED_LINE_CHARS = 2000

# One long line is not enough — a legitimate source file can carry a single
# embedded blob (data: URI, generated regex, inlined SVG) and must stay in the
# scan. Require the long lines to hold most of the file's characters. Measured
# on the same corpus: every generated bundle scored >= 0.72 (the one hand-written
# file carrying a large blob would have scored far below), so 0.5 sits in the
# empty band between the two populations.
_MINIFIED_CHAR_FRACTION = 0.5

# Only bundler-produced text types are content-classified. Prose, data and
# config formats (.md, .json, .sql, .yaml) legitimately carry very long lines,
# and excluding those would silently drop real coverage.
_MINIFIABLE_SUFFIXES = frozenset({
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".css", ".scss", ".less",
})


def _long_line_chars(lines: tuple[str, ...]) -> tuple[int, int]:
    """Return (chars on over-long lines, total chars) for ``lines``."""
    long_chars = sum(len(ln) for ln in lines if len(ln) > _MINIFIED_LINE_CHARS)
    return long_chars, sum(len(ln) for ln in lines)


def is_minified_content(path: Path) -> bool:
    """Return True when the file's *shape* is that of a generated bundle.

    Complements :func:`is_minified_name` for hash-named chunk files. Uses the
    shared cached read, so the file is never read twice: any skill that goes on
    to analyse it hits the same cache entry. A file too large for the read cap
    is unreadable here and reported as not-minified — no skill can analyse it
    either, so it produces no findings regardless.
    """
    if effective_suffix(path.name) not in _MINIFIABLE_SUFFIXES:
        return False
    lines = read_file_lines(path)
    if not lines:
        return False
    long_chars, total = _long_line_chars(lines)
    if not long_chars:
        return False
    return long_chars >= total * _MINIFIED_CHAR_FRACTION


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


def _collect_capped(
    paths: Iterable[Path], max_files: int, source_path: str, label: str, advice: str,
) -> tuple[Path, ...]:
    """Accumulate ``paths`` up to ``max_files``, logging a truncation warning.

    Shared by the backup and all-files walks so the cap-and-warn contract lives
    in exactly one place: a silent truncation reads as full coverage when it is
    not, so the warning must never depend on which caller ran.
    """
    files: list[Path] = []
    for p in paths:
        files.append(p)
        if len(files) >= max_files:
            logger.warning(
                "%s_truncated path=%s files=%d max=%d — coverage is PARTIAL; %s",
                label, source_path, len(files), max_files, advice,
            )
            break
    logger.info("%s_complete path=%s files=%d", label, source_path, len(files))
    return tuple(files)


def _walk_unfiltered_by_extension(source_path: str) -> Iterable[Path]:
    """The shared walk primitive: SKIP_DIRS + ignore spec, no extension gate."""
    root = Path(source_path)
    if not root.is_dir():
        return ()
    return _walk_filtered(root, root, _load_ignore_spec(str(root)))


def scan_autorun_files(source_path: str) -> list[Path]:
    """Every editor / IDE / devcontainer autorun file under ``source_path``.

    Deliberately independent of the extension allowlist, exactly as
    :func:`scan_backup_files` is: membership is decided by the PATH, not by the
    file type, and a `.claude/hooks/` entry routinely carries no extension at
    all. The walk itself still applies SKIP_DIRS, the ignore spec and
    """
    return list(_scan_autorun_files_cached(source_path))


@lru_cache(maxsize=16)
def _scan_autorun_files_cached(source_path: str) -> tuple[Path, ...]:
    """Cached inner autorun walk — keyed by path."""
    root = Path(source_path)
    if not root.is_dir():
        return ()
    spec = _load_ignore_spec(str(root))
    return tuple(
        p for p in _walk_filtered(root, root, spec) if is_autorun_entry(root, p)
    )


@lru_cache(maxsize=16)
def _scan_backup_files_cached(source_path: str, max_files: int) -> tuple[Path, ...]:
    """Cached inner backup walk — keyed by (path, max_files)."""
    return _collect_capped(
        (p for p in _walk_unfiltered_by_extension(source_path) if is_backup_name(p.name)),
        max_files, source_path, "backup_scan",
        "raise VULTURE_MAX_FILES to enumerate every shadow copy",
    )


def scan_all_files(source_path: str, max_files: int = MAX_FILES) -> list[Path]:
    """Return every file under ``source_path``, ignoring the extension allowlist.

    Same rationale as :func:`scan_backup_files`, generalised: a file's *exposure*
    is a property of its name and location, not of whether we can parse it. A
    readable ``.kdbx`` or ``.key`` in a served tree leaks its contents even though
    no skill would ever tokenise it, and the extension allowlist means the normal
    per-file loop never sees it.

    SKIP_DIRS and the ignore spec still apply, so vendored and ignored trees are
    excluded as usual.
    """
    return list(_scan_all_files_cached(source_path, max_files))


@lru_cache(maxsize=16)
def _scan_all_files_cached(source_path: str, max_files: int) -> tuple[Path, ...]:
    """Cached inner all-files walk — keyed by (path, max_files)."""
    return _collect_capped(
        _walk_unfiltered_by_extension(source_path), max_files, source_path,
        "all_files_scan", "raise VULTURE_MAX_FILES for full enumeration",
    )


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


# Feature 0091 §6.5: the root-relative prefixes each scan refused to descend
# into, keyed by the scanned root. The backend subtracts these from the scan's
# scope: without them it cannot tell "this scan proved nothing is there" from
# "this scan never looked", and the latter would close every lineage row under
# a pruned tree. Keyed by root (not per-call) because the walk itself is
# lru_cached — a second skill scanning the same tree reuses the cached walk and
# would otherwise record nothing. Cleared with the walk caches.
_PRUNED_LOCK = threading.Lock()
_PRUNED_DIRS: dict[str, set[str]] = {}


def _rel_of(scan_root: Path, entry: Path) -> str:
    """``entry`` as a root-relative POSIX path, or ``""`` if it is outside."""
    try:
        return entry.relative_to(scan_root).as_posix()
    except ValueError:
        return ""


def _record_pruned(scan_root: Path, entry: Path) -> None:
    """Remember one prefix the walk did not look inside (or at).

    Usually a directory. Inside a restricted (autorun-only) directory it is
    also the individual FILES that were not read: the container itself was
    walked, so reporting it as a blanket prefix would put the autorun file we
    DID read out of scope, and an out-of-scope row can never close.
    """
    rel = _rel_of(scan_root, entry)
    if not rel or rel == ".":
        return
    with _PRUNED_LOCK:
        _PRUNED_DIRS.setdefault(str(scan_root), set()).add(rel)


def pruned_dirs(source_path: str) -> list[str]:
    """Root-relative prefixes the walker skipped under ``source_path``.

    Root-relative and never absolute: the backend joins these onto the scanned
    root it already knows, and cannot do that with a host path.
    """
    with _PRUNED_LOCK:
        return sorted(_PRUNED_DIRS.get(str(Path(source_path)), set()))


def _prune(scan_root: Path, entry: Path) -> str:
    """Record ``entry`` when it is a directory, and classify it as skipped."""
    if entry.is_dir():
        _record_pruned(scan_root, entry)
    return "skip"


def _excluded_entry(entry: Path, scan_root: Path, spec) -> bool:
    """A symlink (loop guard) or an ignore-spec match: never walked, never yielded."""
    return entry.is_symlink() or _is_path_ignored(entry, scan_root, spec)


def _pruned_dir_name(name: str) -> bool:
    """A directory name the hardcoded baseline never descends into."""
    return name in SKIP_DIRS or _is_backup_dir(name)


def _classify_file(entry: Path, scan_root: Path, restricted: bool) -> str:
    """``"file"`` / ``"skip"`` for one walked FILE.

    Inside a restricted directory — one the walker entered ONLY to reach an
    autorun file — every other file is left unread and recorded, so the backend
    can still tell "read it and the finding is gone" from "never opened it".
    """
    if not restricted:
        return "file"
    if is_autorun_entry(scan_root, entry):
        return "file"
    _record_pruned(scan_root, entry)
    return "skip"


def _classify_pruned_dir(scan_root: Path, entry: Path, rel: str) -> str:
    """A ``SKIP_DIRS`` name: entered ONLY when D2 needs an autorun file inside
    it, and then only for that file."""
    if _is_autorun_dir(rel):
        return "restricted"
    return _prune(scan_root, entry)


def _classify_dir(entry: Path, scan_root: Path, restricted: bool) -> str:
    """``"dir"`` / ``"restricted"`` / ``"skip"`` for one walked DIRECTORY."""
    rel = _rel_of(scan_root, entry)
    if restricted:
        return "restricted" if _is_autorun_dir(rel) else _prune(scan_root, entry)
    if not _pruned_dir_name(entry.name):
        return "dir"
    return _classify_pruned_dir(scan_root, entry, rel)


def _classify_entry(entry: Path, scan_root: Path, spec, restricted: bool = False) -> str:
    """``"file"`` / ``"dir"`` / ``"restricted"`` / ``"skip"`` for one entry.

    Split out of :func:`_walk_filtered` so that every reason a path is not
    looked at passes through exactly one recording point — a prune the walker
    performs but does not report is a lineage row the backend closes without
    evidence.

    Order matters: the name test is applied only after the entry is known to be
    a directory, because ``SKIP_DIRS`` holds bare names (``data``, ``fixtures``)
    that a FILE may legitimately carry.
    """
    if _excluded_entry(entry, scan_root, spec):
        return _prune(scan_root, entry)
    if entry.is_file():
        return _classify_file(entry, scan_root, restricted)
    if not entry.is_dir():
        return "skip"
    return _classify_dir(entry, scan_root, restricted)


def _sorted_entries(root: Path) -> list[Path]:
    """``root``'s children in a stable order, or nothing if unreadable."""
    try:
        return sorted(root.iterdir())
    except PermissionError:
        return []


def _walk_filtered(
    root: Path, scan_root: Path, spec, restricted: bool = False,
) -> Iterator[Path]:
    """Walk directory tree, skipping ignored directories.

    Skips entries that:
    - Are in :data:`SKIP_DIRS` or :data:`SKIP_FILES` (hardcoded baseline).
    - Match a `.vultureignore` / `.gitignore` pattern from ``scan_root``.
    - Are symlinks (avoid loops).
    - Are backup directories (`-backup`, `_old`, etc.).

    Feature 0091 D2 carves ONE hole in that: a pruned directory on the path to
    a :data:`WELL_KNOWN_AUTORUN_FILES` entry is entered in ``restricted`` mode
    and yields those files and nothing else.

    Every prefix the walk did not look inside is recorded (feature 0091 §6.5)
    and readable back through :func:`pruned_dirs`.
    """
    dirs: list[tuple[Path, bool]] = []
    for entry in _sorted_entries(root):
        kind = _classify_entry(entry, scan_root, spec, restricted)
        if kind == "file":
            yield entry
        elif kind in ("dir", "restricted"):
            dirs.append((entry, kind == "restricted"))

    for directory, child_restricted in dirs:
        yield from _walk_filtered(directory, scan_root, spec, child_restricted)


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


_PROSE_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".adoc", ".txt"})


def is_prose_file(path: Path) -> bool:
    """True for documentation prose, where a code pattern is a *mention*.

    Code-pattern skills must skip these. A hardening guide saying "never set
    ``StrictHostKeyChecking=no``" is not an instance of setting it, and
    ``COMMENT_INDICATORS`` cannot help: markdown body text carries no comment
    marker, so prose reads as executable source. Measured on a pure
    ``SECURITY.md`` + ``README.rst`` pair that only *condemns* insecure options:
    three findings (CWE-269, CWE-328, CWE-94), all false.

    **Deliberately NOT applied to secret scanning.** A credential pasted into a
    README is a genuine leak — the value is exposed whether or not anything
    executes. Prose suppresses pattern-shaped findings, never exposed values.

    Uses :func:`effective_suffix`, so a shadow copy (``notes.md.bak``) is prose
    too.
    """
    return effective_suffix(path.name) in _PROSE_SUFFIXES


def is_type_declaration_file(path: Path) -> bool:
    """True for a TypeScript declaration file (``*.d.ts`` and friends).

    Matched on the NAME, not the suffix: ``Path("api.d.ts").suffix`` is only
    ``.ts``. A declaration file contains signatures, never executable code, so a
    detector that matches an identifier followed by a paren will report every
    declared method as a call — which is how ``eval(script: string, ...)`` on a
    Redis client interface became a CRITICAL code-injection finding.
    """
    name = path.name.lower()
    return any(name.endswith(ext) for ext in (".d.ts", ".d.mts", ".d.cts"))


def is_story_file(path: Path) -> bool:
    """True for Storybook stories, whose constants are display fixtures.

    Deliberately NOT used to suppress secret scanning — a real credential
    committed in a story is still exposed. Same reasoning as
    :func:`is_prose_file`.
    """
    name = path.name.lower()
    if any(part.lower() == "stories" for part in path.parts):
        return True
    return any(
        f".{kind}.{ext}" in name
        for kind in ("stories", "story")
        for ext in ("ts", "tsx", "js", "jsx", "mdx")
    )


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
    # These two were omitted before, so a second audit in the same process could
    # score a stale tree. Clearing more is always safe.
    _scan_backup_files_cached.cache_clear()
    _scan_all_files_cached.cache_clear()
    _scan_autorun_files_cached.cache_clear()
    # Feature 0091 §6.5: the pruned-prefix record is produced BY those walks and
    # keyed the same way, so it must be dropped with them — a stale entry would
    # report the previous run's tree as out of scope for this one.
    with _PRUNED_LOCK:
        _PRUNED_DIRS.clear()
    # Feature 0076: the anchor verifier caches the NORMALISED form of the same
    # files, keyed the same way. Imported at call time — `shared.anchor` imports
    # `shared.tools.line_format`, so a module-level import here would close a
    # cycle through this package's __init__.
    from shared.anchor import clear_cache as _clear_anchor_cache

    _clear_anchor_cache()


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
