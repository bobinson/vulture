"""Smart file scanner that handles large repositories efficiently."""

import contextvars
import fnmatch
import logging
import os
import re
import sys
import threading
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from functools import lru_cache
from pathlib import Path
from typing import Any, NamedTuple

# Shared line-classification patterns used across all skill files.
# Defined here once to satisfy DRY — import from this module.
SCANNER_DEF_LINE = re.compile(r"re\.compile\(|=\s*\[?\s*re\.", re.IGNORECASE)
SAFE_IMPORT_LINE = re.compile(r"^\s*(?:from|import)\s")
COMMENT_INDICATORS = re.compile(r"^\s*(#|//|/?\*|\*|<!--)")


def opens_pattern_definition(line: str) -> bool:
    """A scanner pattern definition left open on ``line`` (``re.compile(`` whose
    argument continues below): the next line is the pattern, not code. The
    per-line ``SCANNER_DEF_LINE`` test sees only the line holding the call."""
    return bool(SCANNER_DEF_LINE.search(line)) and line.count("(") > line.count(")")


def is_non_code_line(line: str, imports: re.Pattern[str]) -> bool:
    """A line a skill's per-line checks skip: a comment, an import by the skill's own
    ``imports`` shape, or a scanner's own pattern definition."""
    return bool(
        COMMENT_INDICATORS.match(line) or imports.match(line) or SCANNER_DEF_LINE.search(line)
    )


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

# The only folder names in code: version-control stores, never walked whatever
# any ignore file says (`.git/config` routinely carries a clone token).
VCS_DIRS = frozenset({".git", ".svn", ".hg", ".bzr"})

# Every other folder skipped by default is a line of this file, in
# `.vultureignore` syntax, and a scanned project brings one back with a
# negation in its root `.vultureignore` (`!build/`). It is a byte-identical
# copy of `default.vultureignore` at the repository root, the file to edit:
# this package is built without the repository root, as are the backend's
# `pkg/scanignore` and the opengrep plugin, which carry the same copy.
DEFAULT_IGNORE_FILE = Path(__file__).with_name("default.vultureignore")


def _default_ignore_globs(path: Path) -> tuple[str, ...]:
    """The directory-name globs of ``path``, one per ``<glob>/`` line.

    Anything else is refused at import: the staging copy and the plugin match
    these against bare directory names, so a negation or a path would mean
    one thing here and another there.
    """
    globs = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            globs.append(_directory_glob(path, line))
    return tuple(globs)


_DIRECTORY_GLOB_LINE = re.compile(r"([^!\\/][^/]*)/")


def _directory_glob(path: Path, line: str) -> str:
    match = _DIRECTORY_GLOB_LINE.fullmatch(line)
    if match is None:
        raise ValueError(f"{path.name}: not a directory-name glob: {line!r}")
    return match.group(1)


DEFAULT_IGNORE_GLOBS = _default_ignore_globs(DEFAULT_IGNORE_FILE)
_DEFAULT_IGNORED = re.compile("|".join(f"(?:{fnmatch.translate(g)})" for g in DEFAULT_IGNORE_GLOBS))

# Every folder NAME skipped by default: the VCS stores and the default ignore
# file's literal names (its globs, such as `*-backup`, are not names).
SKIP_DIRS = VCS_DIRS | frozenset(g for g in DEFAULT_IGNORE_GLOBS if not set(g) & set("*?["))


def ignored_by_default(name: str) -> bool:
    """Whether a folder called ``name`` is skipped when no project ignore file
    says otherwise: a VCS store, or a folder the default ignore file lists."""
    return name in VCS_DIRS or _DEFAULT_IGNORED.match(name) is not None


# The file every Python virtualenv carries (PEP 405): a directory holding it is
# an installed environment whatever it is called, and is never walked.
VIRTUALENV_MARKER = "pyvenv.cfg"

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
#
# EVIDENCE GATE (0074 P6): no extension enters this default set without >= 20 cited
# sites across >= 2 targets showing zero labelled-real findings, adjudicated under the
# numbered presentation. Below that bar an exclusion deletes findings nobody measured.
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
    return not _exclusion(path, exts, extras, scan_minified)


def _exclusion(
    path: Path, exts: frozenset[str], extras: frozenset[str], scan_minified: bool,
) -> str:
    """Why ``path`` is outside the scan set, or ``""`` when it is in it."""
    eff_name = effective_name(path.name)
    if not _wanted_by_name(path.name, effective_suffix(path.name), eff_name, exts, extras):
        return "extension outside the scan set"
    return _minified_exclusion(path, eff_name, scan_minified)


def _minified_exclusion(path: Path, eff_name: str, scan_minified: bool) -> str:
    if scan_minified or not (is_minified_name(eff_name) or is_minified_content(path)):
        return ""
    return "minified or bundled artefact"


def scan_set_exclusion(
    path: Path, readers: tuple[tuple[frozenset[str], frozenset[str]], ...] = (),
) -> str:
    """Why the walker's default scan set leaves ``path`` out, or ``""`` when it
    takes it: the same predicate the walker applies, so a caller reporting a
    file as not scanned names the scanner's own reason rather than a guess.

    ``readers`` are the ``(extensions, extra_filenames)`` of skills that walk
    with sets of their own (the secret scan reads ``.env.*`` and key files by
    name): ``path`` is in the scan set when ANY of them takes it.
    """
    scan_minified = _scan_minified()
    sets = ((default_extensions(), WELL_KNOWN_FILENAMES), *readers)
    reasons = [_exclusion(path, exts, extras, scan_minified) for exts, extras in sets]
    return "" if "" in reasons else reasons[0]


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


def _walk_entries(source_path: str) -> Iterable[tuple[Path, bool]]:
    """The shared walk primitive: SKIP_DIRS + ignore spec, no extension gate.

    Every file it yields (``False``) and every directory it enters (``True``).
    """
    root = Path(source_path)
    if not root.is_dir():
        return ()
    return _walk_tree(root, root, _load_ignore_spec(str(root)))


def _walk_unfiltered_by_extension(source_path: str) -> Iterable[Path]:
    """The files of :func:`_walk_entries`."""
    return (entry for entry, is_dir in _walk_entries(source_path) if not is_dir)


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
    excluded as usual. The same cached walk answers :func:`tree_files`.
    """
    return list(_scan_all_files_cached(source_path, max_files))


@lru_cache(maxsize=16)
def _scan_all_files_cached(source_path: str, max_files: int) -> tuple[Path, ...]:
    """Cached inner all-files walk — keyed by (path, max_files)."""
    return _tree_listing(source_path, max_files).files


class _Listing(NamedTuple):
    """One walk of a tree: its files and the directories it entered, each with
    its root-relative POSIX path (computed once, so a query is string work),
    and whether the file cap cut the walk short."""

    files: tuple[Path, ...]
    file_rels: tuple[str, ...]
    dirs: tuple[Path, ...]
    dir_rels: tuple[str, ...]
    truncated: bool


@lru_cache(maxsize=16)
def _tree_listing(source_path: str, max_files: int) -> _Listing:
    """Every file the walk yields, capped at ``max_files`` as
    :func:`scan_all_files` always was, and every directory it entered on the way."""
    root = Path(source_path)
    dirs: list[Path] = []
    files = _collect_capped(
        _files_noting_dirs(_walk_entries(source_path), dirs), max_files, source_path,
        "all_files_scan", "raise VULTURE_MAX_FILES for full enumeration",
    )
    return _Listing(
        files, tuple(_rel_of(root, p) for p in files),
        tuple(dirs), tuple(_rel_of(root, d) for d in dirs),
        len(files) >= max_files,
    )


def _files_noting_dirs(entries: Iterable[tuple[Path, bool]], dirs: list[Path]) -> Iterator[Path]:
    """The files of ``entries``; each directory among them is appended to ``dirs``."""
    for entry, is_dir in entries:
        if is_dir:
            dirs.append(entry)
        else:
            yield entry


def tree_files(
    source_path: str | Path, *, under: str = "", depth: int | None = None,
    names: Iterable[str] = (), globs: Iterable[str] = (),
) -> Iterator[Path]:
    """The walked files of the scan root ``source_path``, filtered.

    What a skill uses instead of its own ``rglob`` / ``iterdir`` / ``os.walk``.
    Any other walk of the scanned tree finds what the audit never reads -- a
    vendored package's ``architecture.md`` under ``.venv`` answered for the
    project's design review -- so this filters the walker's own listing: the one
    :func:`scan_all_files` returns, cached per root. It is always walked from
    the scan ROOT, so a subdirectory query keeps the root's ``.vultureignore``
    and every ``.gitignore`` above it.

    The cached listing is capped at ``MAX_FILES`` and counts every file, data
    and images included. A query must still be complete -- a capped listing
    would make evidence beyond the cap look absent -- so when the listing was
    cut short, the query walks the tree itself, lazily and uncapped.

    Args:
        source_path: The scan root.
        under: A root-relative directory to look inside; ``""`` (or ``"."``)
            is the whole tree.
        depth: How many levels below ``under``: 1 lists its direct children,
            as ``iterdir`` does; ``None`` is any depth.
        names: Exact basenames to keep.
        globs: ``fnmatchcase`` basename patterns to keep, with the semantics of
            ``rglob(pattern)`` for a pattern without a separator.
            A file matching either ``names`` or ``globs`` is kept; with neither,
            every file is.
    """
    entries = _query_entries(str(Path(source_path)), under, depth, want_dirs=False)
    return _select(entries, under, depth, _basename_test(names, globs))


def tree_dirs(
    source_path: str | Path, *, under: str = "", depth: int | None = None,
    names: Iterable[str] = (), globs: Iterable[str] = (),
) -> Iterator[Path]:
    """The directories the walk of ``source_path`` enters, filtered exactly as
    :func:`tree_files` filters files. An empty directory is listed: its
    presence alone can be the evidence a skill looks for."""
    entries = _query_entries(str(Path(source_path)), under, depth, want_dirs=True)
    return _select(entries, under, depth, _basename_test(names, globs))


def _query_entries(
    source_path: str, under: str, depth: int | None, want_dirs: bool,
) -> Iterable[tuple[Path, str]]:
    """The (path, root-relative path) pairs a query filters: the cached
    listing, or the uncapped walk when the listing was cut short."""
    listing = _tree_listing(source_path, MAX_FILES)
    if listing.truncated:
        return _uncapped(source_path, under, depth, want_dirs)
    if want_dirs:
        return zip(listing.dirs, listing.dir_rels)
    return zip(listing.files, listing.file_rels)


def _uncapped(
    source_path: str, under: str, depth: int | None, want_dirs: bool,
) -> Iterator[tuple[Path, str]]:
    """The walk itself below ``under``, uncapped and recording nothing (a query
    is not the audit's walk), one level only for ``depth == 1``."""
    root = Path(source_path)
    start = _entered(root, _under_parts(under), _classify_on_disk)
    if start is None:
        return
    for entry, is_dir in _walk_below(root, start, shallow=depth == 1):
        if is_dir == want_dirs:
            yield entry, _rel_of(root, entry)


def _walk_below(
    scan_root: Path, state: tuple[Path, Any, bool], shallow: bool,
) -> Iterator[tuple[Path, bool]]:
    """The walk from an entered directory: its children only, or all below it."""
    directory, rules, restricted = state
    if shallow:
        children = _kept_children(directory, scan_root, rules, restricted, _no_record)
        return ((entry, kind != "file") for entry, kind in children)
    return _walk_tree(directory, scan_root, rules, restricted, _no_record)


def _select(
    entries: Iterable[tuple[Path, str]], under: str, depth: int | None,
    wanted: Callable[[str], bool],
) -> Iterator[Path]:
    """The entries below ``under`` (within ``depth``) whose basename is ``wanted``."""
    prefix = _under_prefix(under)
    for path, rel in entries:
        if _in_scope(rel, prefix, depth) and wanted(path.name):
            yield path


def _under_prefix(under: str) -> str:
    """``under`` as the prefix of the root-relative paths below it."""
    base = under.strip("/")
    return "" if base in ("", ".") else base + "/"


def _under_parts(under: str) -> tuple[str, ...]:
    """``under`` as path segments below the root."""
    return tuple(part for part in under.split("/") if part not in ("", "."))


def _in_scope(rel: str, prefix: str, depth: int | None) -> bool:
    """Whether root-relative ``rel`` lies below ``prefix``, within ``depth``."""
    return rel.startswith(prefix) and (depth is None or rel.count("/", len(prefix)) < depth)


def _basename_test(names: Iterable[str], globs: Iterable[str]) -> Callable[[str], bool]:
    """A basename predicate: in ``names`` or matching a glob; everything when both are empty."""
    exact, patterns = frozenset(names), tuple(globs)
    if not (exact or patterns):
        return lambda _name: True
    matches = _glob_matcher(patterns)
    return lambda name: name in exact or matches(name)


def _glob_matcher(patterns: tuple[str, ...]) -> Callable[[str], bool]:
    """``fnmatchcase`` against any of ``patterns``, as ONE compiled regex: a
    query runs over every walked file, so it is one match per name, not one
    per pattern."""
    if not patterns:
        return lambda _name: False
    regex = re.compile("|".join(f"(?:{fnmatch.translate(p)})" for p in patterns))
    return lambda name: regex.match(name) is not None


def walk_reaches(scan_root: str | Path, path: str | Path) -> bool:
    """Whether the walk of ``scan_root`` yields ``path`` (a file) or enters it
    (a directory).

    The walker's own verdict for one path, without walking the tree: each step
    down from the root is classified by the same function the walk uses, with
    the state the walk carries there (the autorun-only restriction, and each
    directory's `.gitignore`). Each step must also be spelled exactly as its
    directory lists it (:func:`_spelled_on_disk`). A probe records nothing in
    :func:`pruned_dirs`: asking about a path is not pruning it. ``False`` for a
    path outside the root, one spelled with ``..``, and one not on disk.
    """
    root, target = Path(scan_root), Path(path)
    rel = _rel_of(root, target)
    if rel == ".":
        return root.is_dir()
    parts = Path(rel).parts
    return bool(parts) and ".." not in parts and _reaches_along(root, parts)


def _reaches_along(scan_root: Path, parts: tuple[str, ...]) -> bool:
    """Follow ``parts`` down from the root as the walk would, entering each
    directory on the way; the last part is reached when the walk would yield
    or enter it."""
    state = _entered(scan_root, parts[:-1], _classify_on_disk)
    if state is None:
        return False
    directory, rules, restricted = state
    return _classify_on_disk(directory / parts[-1], scan_root, rules, restricted, False) in _REACHED


def walk_excludes(scan_root: str | Path, path: str | Path) -> bool:
    """Whether a rule of the walk keeps it from ``path``, whether or not
    ``path`` exists.

    By name and rules alone: every component above ``path`` is judged as the
    directory it would have to be, and ``path`` as a file. For a caller that
    must give a missing path the answer an existing one would get, so the
    answer cannot reveal whether a hidden file exists.
    """
    root = Path(scan_root)
    parts = Path(_rel_of(root, Path(path))).parts
    if not parts:
        return False
    state = _entered(root, parts[:-1], _classify_as)
    if state is None:
        return True
    directory, rules, restricted = state
    return _classify_as(directory / parts[-1], root, rules, restricted, False) != "file"


def _entered(
    scan_root: Path, parts: tuple[str, ...], classify: Callable[..., str],
) -> tuple[Path, Any, bool] | None:
    """The directory ``parts`` names below the root, with the walk's state
    inside it (its ignore rules, the autorun-only restriction), or ``None``
    when ``classify`` says the walk would not enter one of them."""
    rules, entry, restricted = _load_ignore_spec(str(scan_root)), scan_root, False
    for part in parts:
        entry = entry / part
        kind = classify(entry, scan_root, rules, restricted, True)
        if kind not in _ENTERED:
            return None
        restricted = kind == "restricted"
        rules = _descend(rules, scan_root, entry)
    return entry, rules, restricted


def _classify_on_disk(entry: Path, scan_root: Path, spec, restricted: bool, _as_dir: bool) -> str:
    """The walk's classification of an entry on disk, as the walk would have
    listed it: a name spelled otherwise than its directory spells it is skipped."""
    if not _spelled_on_disk(entry):
        return "skip"
    return _classify_entry(entry, scan_root, spec, restricted)


def _spelled_on_disk(entry: Path) -> bool:
    """Whether ``entry``'s name appears, spelled exactly so, in its directory.

    On a case-insensitive filesystem ``.GIT/config`` opens ``.git/config``,
    while every rule the walk applies -- SKIP_DIRS, SKIP_FILES, the ignore
    files -- compares spellings. The walk only ever sees names as the
    directory lists them, so a probe may reach a path only spelled that way.
    """
    try:
        return entry.name in os.listdir(entry.parent)
    except OSError:
        return False


def present(source_path: str | Path, rel: str) -> bool:
    """Whether the fixed root-relative location ``rel`` -- a file or a
    directory -- exists where the walk reaches it.

    For a probe such as ``SECURITY.md`` or ``.husky``: the evidence counts only
    where the audit reads. SKIP_FILES is deliberately not consulted -- it names
    files the code scan never PARSES, which the walk still reaches, and a lock
    file is exactly what the lock-file probe looks for.
    """
    return walk_reaches(source_path, Path(source_path) / rel)


def _compile_ignore_lines(lines: list[str]):
    """A gitignore-syntax ``PathSpec`` for ``lines``, or None when there are none."""
    import pathspec

    if not lines:
        return None
    # Use the newer "gitignore" style introduced in pathspec 0.12; the
    # legacy "gitwildmatch" name was deprecated in pathspec 1.x. Fall
    # back to gitwildmatch for pathspec < 0.12 (which doesn't expose
    # gitignore) so we don't break older installs.
    try:
        return pathspec.PathSpec.from_lines("gitignore", lines)
    except (ValueError, LookupError):
        return pathspec.PathSpec.from_lines("gitwildmatch", lines)


def _read_lines(path: Path) -> list[str]:
    """The lines of one ignore file; nothing when it is absent, unreadable or a
    symlink. Git does not follow a symlinked `.gitignore`, and following one
    would read rules from outside the scanned tree."""
    if path.is_symlink() or not path.is_file():
        return []
    try:
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []


@lru_cache(maxsize=4096)
def _gitignore_spec(directory: str):
    """The compiled `.gitignore` of ``directory``, or None.

    Cached because every walk of a tree (code, all files, backups, autorun,
    pattern search) passes each directory; cleared per audit by
    :func:`clear_caches`.
    """
    return _compile_ignore_lines(_read_lines(Path(directory) / ".gitignore"))


def _verdict(spec, rel: str) -> bool | None:
    """True if ``spec`` ignores ``rel``, False if a negation re-includes it,
    None if no pattern matched."""
    return None if spec is None else spec.check_file(rel).include


def _below(base: str, rel: str) -> str:
    """Root-relative ``rel`` made relative to the root-relative directory ``base``."""
    return rel[len(base) + 1:] if base else rel


@dataclass(frozen=True, eq=False)
class IgnoreRules:
    """The ignore files in force in one directory of a walk (gitignore(5)).

    ``gitignores`` pairs each `.gitignore` between the scan root and that
    directory, shallowest first, with the root-relative directory its patterns
    are relative to (``""`` for the root). The deepest one whose patterns match
    decides, and within it the last matching pattern. ``vultureignore`` is the
    root's `.vultureignore` and overrides them all, the default ignore file
    (:data:`DEFAULT_IGNORE_FILE`) included. A `.gitignore` inside an ignored
    directory is never read, because the walk never enters it: git cannot
    re-include a path whose parent directory is excluded either.
    """

    gitignores: tuple[tuple[str, Any], ...] = ()
    vultureignore: Any = None
    read_gitignore: bool = True

    def descend(self, rel_dir: str, directory: Path) -> "IgnoreRules":
        """The rules in force inside ``directory`` (root-relative ``rel_dir``)."""
        spec = _gitignore_spec(str(directory)) if self.read_gitignore else None
        if spec is None:
            return self
        return replace(self, gitignores=(*self.gitignores, (rel_dir, spec)))

    def ignored(self, rel: str, is_dir: bool) -> bool:
        """Whether root-relative ``rel`` is ignored where it sits."""
        key = f"{rel}/" if is_dir else rel
        for base, spec in (("", self.vultureignore), *reversed(self.gitignores)):
            verdict = _verdict(spec, _below(base, key))
            if verdict is not None:
                return verdict
        return False

    def brings_back(self, rel_dir: str) -> bool:
        """Whether the root `.vultureignore` re-includes the directory
        ``rel_dir`` (its last matching pattern is a negation), which overrides
        the default ignore file. A `.gitignore` never does."""
        return _verdict(self.vultureignore, f"{rel_dir}/") is False


@lru_cache(maxsize=16)
def _load_ignore_spec(source_path: str) -> IgnoreRules | None:
    """The ignore rules in force at the scan root ``source_path``.

    Honors its `.gitignore` by default (set ``VULTURE_IGNORE_GITIGNORE=true``
    to disable every `.gitignore`, nested ones included) and its
    `.vultureignore` always when present. A walk extends the rules with each
    nested `.gitignore` through :meth:`IgnoreRules.descend`.

    Returns None only when pathspec isn't installed.
    """
    try:
        import pathspec  # noqa: F401
    except ImportError:
        return None

    root = Path(source_path)
    rules = IgnoreRules(
        vultureignore=_compile_ignore_lines(_read_lines(root / ".vultureignore")),
        read_gitignore=os.environ.get("VULTURE_IGNORE_GITIGNORE", "").lower() != "true",
    )
    return rules.descend("", root)


def _descend(rules: IgnoreRules | None, scan_root: Path, directory: Path) -> IgnoreRules | None:
    """``rules`` extended by ``directory``'s own `.gitignore`, for the walk inside it."""
    return None if rules is None else rules.descend(_rel_of(scan_root, directory), directory)


def path_ignored(scan_root: Path, path: Path, rules: IgnoreRules | None = None) -> bool:
    """Whether the walk of ``scan_root`` skips ``path`` because of an ignore file.

    It does when ``path``, or a directory the walk would have to enter to reach
    it, is ignored by the rules in force where it sits. By the rules alone, so
    it answers for a path that does not exist too (the tools' confinement asks
    it of one, :mod:`shared.tools.confine`); :func:`walk_reaches` is the whole
    verdict for one that does. ``rules`` defaults to the root's.
    """
    rules = _load_ignore_spec(str(scan_root)) if rules is None else rules
    rel = _rel_of(scan_root, path)
    if rules is None or rel in ("", "."):
        return False
    return _ignored_along(scan_root, Path(rel).parts, rules)


def _ignored_along(scan_root: Path, parts: tuple[str, ...], rules: IgnoreRules) -> bool:
    """Follow ``parts`` down from the root as the walk would: ignored as soon as
    an entry on the way is, each tested by the rules in force where it sits."""
    entry = scan_root
    for i, part in enumerate(parts[:-1]):
        entry = entry / part
        if _is_path_ignored(entry, scan_root, rules):
            return True
        rules = rules.descend("/".join(parts[:i + 1]), entry)
    return _is_path_ignored(scan_root.joinpath(*parts), scan_root, rules)


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


# What :func:`_classify_entry` answers. Classification is PURE: ``_PRUNED`` is a
# skip the walk must record (a directory it did not look inside, or a file left
# unread inside an autorun-only directory), and only the walk records it, so
# :func:`walk_reaches` can ask the same question about one path without
# reporting a prune the scan never made.
_PRUNED = "pruned"
_ENTERED = frozenset({"dir", "restricted"})
_REACHED = _ENTERED | {"file"}


def _prune(entry: Path) -> str:
    """Skip ``entry``; a directory is recorded by the walk as a pruned prefix."""
    return _PRUNED if entry.is_dir() else "skip"


def _no_record(_scan_root: Path, _entry: Path) -> None:
    """The prune sink of a query's walk: what a query skips is not reported."""


def _pruned_dir(entry: Path, rel: str, spec: IgnoreRules | None) -> bool:
    """A directory no project ignore file excludes that the walk still does not
    descend into: a VCS store or a virtualenv always, and a folder of the
    default ignore file unless the root `.vultureignore` brings it back."""
    if entry.name in VCS_DIRS or (entry / VIRTUALENV_MARKER).is_file():
        return True
    return ignored_by_default(entry.name) and not _brought_back(spec, rel)


def _brought_back(spec: IgnoreRules | None, rel: str) -> bool:
    return spec is not None and spec.brings_back(rel)


def _classify_file(entry: Path, scan_root: Path, restricted: bool) -> str:
    """``"file"`` / ``_PRUNED`` for one walked FILE.

    Inside a restricted directory — one the walker entered ONLY to reach an
    autorun file — every other file is left unread and recorded, so the backend
    can still tell "read it and the finding is gone" from "never opened it".
    """
    if not restricted:
        return "file"
    if is_autorun_entry(scan_root, entry):
        return "file"
    return _PRUNED


def _classify_pruned_dir(entry: Path, rel: str) -> str:
    """A pruned directory: entered ONLY when D2 needs an autorun file inside
    it, and then only for that file."""
    if _is_autorun_dir(rel):
        return "restricted"
    return _prune(entry)


def _classify_dir(entry: Path, scan_root: Path, spec, restricted: bool) -> str:
    """``"dir"`` / ``"restricted"`` / ``_PRUNED`` for one walked DIRECTORY."""
    rel = _rel_of(scan_root, entry)
    if restricted:
        return "restricted" if _is_autorun_dir(rel) else _prune(entry)
    if not _pruned_dir(entry, rel, spec):
        return "dir"
    return _classify_pruned_dir(entry, rel)


def _classify_entry(entry: Path, scan_root: Path, spec, restricted: bool = False) -> str:
    """``"file"`` / ``"dir"`` / ``"restricted"`` / ``_PRUNED`` / ``"skip"`` for one entry.

    Split out of the walk so that every reason a path is not looked at passes
    through one classification, and every ``_PRUNED`` through one recording
    point (:func:`_kept_children`) — a prune the walker performs but does not
    report is a lineage row the backend closes without evidence.

    Order matters: the name test is applied only after the entry is known to be
    a directory, because the default ignore file lists bare names (``dist``,
    ``fixtures``) that a FILE may legitimately carry.
    """
    if entry.is_symlink():  # loop guard: never walked, never yielded
        return _prune(entry)
    if entry.is_file():
        return _classify_as(entry, scan_root, spec, restricted, False)
    if not entry.is_dir():
        return "skip"
    return _classify_as(entry, scan_root, spec, restricted, True)


def _classify_as(entry: Path, scan_root: Path, spec, restricted: bool, as_dir: bool) -> str:
    """The walk's verdict on ``entry`` as a directory (``as_dir``) or a file,
    by name and ignore rules alone: an entry on disk is classified through
    here, and a path that does not exist is judged as what it would be."""
    if _ignored_as(spec, _rel_of(scan_root, entry), as_dir):
        return _PRUNED if as_dir else "skip"
    if as_dir:
        return _classify_dir(entry, scan_root, spec, restricted)
    return _classify_file(entry, scan_root, restricted)


def _ignored_as(spec: IgnoreRules | None, rel: str, as_dir: bool) -> bool:
    return spec is not None and spec.ignored(rel, as_dir)


def _sorted_entries(root: Path) -> list[Path]:
    """``root``'s children in a stable order, or nothing if unreadable."""
    try:
        return sorted(root.iterdir())
    except PermissionError:
        return []


def _kept_children(
    root: Path, scan_root: Path, spec, restricted: bool,
    on_prune: Callable[[Path, Path], None] = _record_pruned,
) -> Iterator[tuple[Path, str]]:
    """``root``'s children the walk keeps, each with its kind; every child it
    prunes goes to ``on_prune`` -- recorded (feature 0091 §6.5) unless the
    walk is a query's."""
    for entry in _sorted_entries(root):
        kind = _classify_entry(entry, scan_root, spec, restricted)
        if kind == _PRUNED:
            on_prune(scan_root, entry)
        elif kind != "skip":
            yield entry, kind


def _walk_tree(
    root: Path, scan_root: Path, spec, restricted: bool = False,
    on_prune: Callable[[Path, Path], None] = _record_pruned,
) -> Iterator[tuple[Path, bool]]:
    """Walk the tree; yield each file (``False``) and each directory entered (``True``).

    Skips entries that:
    - Are ignored by the root's `.vultureignore` or by a `.gitignore` in any
      directory above them, as git applies it (:class:`IgnoreRules`).
    - Are directories the default ignore file lists (:data:`DEFAULT_IGNORE_FILE`:
      dependencies, build output, caches, test data, backup copies, ...), unless
      the root `.vultureignore` brings them back.
    - Are version-control stores (:data:`VCS_DIRS`) or virtualenvs, whatever
      their name (:data:`VIRTUALENV_MARKER`).
      :data:`SKIP_FILES` is not the walker's: the code-file scan applies it.
    - Are symlinks (avoid loops).

    Feature 0091 D2 carves ONE hole in that: a pruned directory on the path to
    a :data:`WELL_KNOWN_AUTORUN_FILES` entry is entered in ``restricted`` mode
    and yields those files and nothing else.

    Every prefix the walk did not look inside is recorded (feature 0091 §6.5)
    and readable back through :func:`pruned_dirs`.
    """
    subdirs: list[tuple[Path, bool]] = []
    for entry, kind in _kept_children(root, scan_root, spec, restricted, on_prune):
        if kind == "file":
            yield entry, False
        else:
            subdirs.append((entry, kind == "restricted"))
    for directory, child_restricted in subdirs:
        yield directory, True
        child_spec = _descend(spec, scan_root, directory)
        yield from _walk_tree(directory, scan_root, child_spec, child_restricted, on_prune)


def _walk_filtered(
    root: Path, scan_root: Path, spec, restricted: bool = False,
) -> Iterator[Path]:
    """The files of :func:`_walk_tree`: every walk of the scanned tree."""
    return (entry for entry, is_dir in _walk_tree(root, scan_root, spec, restricted) if not is_dir)


def _is_path_ignored(entry: Path, scan_root: Path, spec: IgnoreRules | None) -> bool:
    """True if ``entry`` is ignored by the rules in force in its directory.

    Directories are matched with a trailing slash for dir-only patterns
    (e.g. `node_modules/`) to apply.
    """
    rel = _rel_of(scan_root, entry)
    if spec is None or rel in ("", "."):
        return False
    return spec.ignored(rel, entry.is_dir())


def read_file_safe(path: Path, max_size: int = MAX_FILE_SIZE) -> str | None:
    """Read a file safely with size limit and in-process caching.

    Args:
        path: File path to read.
        max_size: Maximum file size in bytes.

    Returns:
        File content as string, or None if unreadable/too large.
    """
    content = _read_file_cached(str(path), max_size)
    _note_read(path, content is not None)
    return content


def read_file_uncached(path: Path, max_size: int = MAX_FILE_SIZE) -> str | None:
    """``read_file_safe`` read from disk now, past its path-keyed cache: the same size cap,
    decode and read recorder. For a caller that keys what it builds on the file's stat
    (the AST model cache, feature 0102 A9), which the cached text of an earlier read in the
    same audit could predate.
    """
    content = _read_file_cached.__wrapped__(str(path), max_size)
    _note_read(path, content is not None)
    return content


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
    _note_read(path, True)
    return result


# Feature 0098: which files did the skills actually READ? A caller that scans a
# chosen set of files (the offline gate) must say which of them were never
# looked at, and the scanner's own reads are the only answer that cannot drift
# from its rules -- extension set, size cap, minified and pruned/ignored paths
# all end in "never read". `None` outside a `record_reads()` block, so the
# ordinary audit path pays one ContextVar lookup per read and records nothing.
_READ_RECORDER: contextvars.ContextVar[set[str] | None] = contextvars.ContextVar(
    "vulture_read_recorder", default=None,
)


def _note_read(path: Path, ok: bool) -> None:
    """Record ``path`` in the active ``record_reads()`` set when it was read."""
    reads = _READ_RECORDER.get()
    if ok and reads is not None:
        reads.add(str(path))


@contextmanager
def record_reads() -> Iterator[set[str]]:
    """Collect the path of every file whose content is read inside the block.

    Only successful reads count: a file over the size cap, or one that cannot
    be read, is not "scanned". Scoped to the current context, so a block in one
    thread does not see another thread's reads.
    """
    reads: set[str] = set()
    token = _READ_RECORDER.set(reads)
    try:
        yield reads
    finally:
        _READ_RECORDER.reset(token)


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
    _tree_listing.cache_clear()
    _scan_autorun_files_cached.cache_clear()
    # The ignore files are read once per audit too: an edited `.gitignore` must
    # apply to the next scan, not to the agent's next restart.
    _load_ignore_spec.cache_clear()
    _gitignore_spec.cache_clear()
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
    _reset_ast_audit_state()
    _reset_l1_memo()


def _reset_l1_memo() -> None:
    """Feature 0104 A2 (S2): drop the validate stage's per-path line and sanitizer memos
    (``context_heuristics.clear_l1_cache``). The AST heads read them in the skill phase
    (``line_signature``) and only the stage's L1 layer cleared them, so an audit that never
    reached it left the next audit reading the files as they were. Only a process that loaded
    the stage has them: one that never did is not made to import it here."""
    heuristics = sys.modules.get("shared.validate.context_heuristics")
    if heuristics is not None:
        heuristics.clear_l1_cache()


def _reset_ast_audit_state() -> None:
    """Feature 0102 (D20, A20): start the AST layer's process-default audit over — its
    tallies, declines, breaker and declined parses (``context.reset_default()``; an entered
    audit is untouched, and ``shared.ast.cache`` says why its models stay). Only a process
    that loaded the layer has any: one that never did is not made to import it here."""
    ast_context = sys.modules.get("shared.ast.context")
    if ast_context is not None:
        ast_context.reset_default()


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
