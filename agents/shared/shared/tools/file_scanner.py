"""Smart file scanner that handles large repositories efficiently."""

from functools import lru_cache
from pathlib import Path
from typing import Iterator

# Directories to always skip
SKIP_DIRS = frozenset({
    ".git", ".svn", ".hg", ".bzr",
    "node_modules", "__pycache__", ".tox", ".nox",
    ".mypy_cache", ".ruff_cache", ".pytest_cache",
    "vendor", "third_party", "dist", "build",
    ".next", ".nuxt", ".output",
    "venv", ".venv", "env", ".env",
    ".idea", ".vscode", ".eclipse",
    "target", "bin", "obj",
    "coverage", ".coverage", "htmlcov",
    ".terraform", ".pulumi",
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
    ".py", ".go", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".rs", ".rb", ".php", ".cs", ".cpp",
    ".c", ".h", ".swift", ".kt", ".scala",
    ".yaml", ".yml", ".toml", ".json", ".xml",
    ".sh", ".bash", ".dockerfile",
})

# Suffixes / patterns for backup directories
_BACKUP_SUFFIXES = ("-backup", "_backup", "-old", "_old", "-bak", "_bak")

MAX_FILES = 500
MAX_FILE_SIZE = 512 * 1024  # 512KB


def scan_code_files(
    source_path: str,
    extensions: frozenset[str] | None = None,
    max_files: int = MAX_FILES,
) -> list[Path]:
    """Scan a directory for code files efficiently.

    Skips common non-code directories, respects file limits,
    and only returns files with relevant extensions.

    Args:
        source_path: Root directory to scan.
        extensions: File extensions to include. Defaults to CODE_EXTENSIONS.
        max_files: Maximum number of files to return.

    Returns:
        List of Path objects for code files found.
    """
    exts = extensions or CODE_EXTENSIONS
    root = Path(source_path)
    if not root.is_dir():
        return []

    files: list[Path] = []
    for p in _walk_filtered(root):
        if p.suffix.lower() in exts and p.name not in SKIP_FILES and p.is_file():
            files.append(p)
            if len(files) >= max_files:
                break
    return files


def _walk_filtered(root: Path) -> Iterator[Path]:
    """Walk directory tree, skipping ignored directories."""
    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        return

    dirs: list[Path] = []
    for entry in entries:
        if entry.is_file():
            yield entry
        elif entry.is_dir() and entry.name not in SKIP_DIRS and not _is_backup_dir(entry.name):
            dirs.append(entry)

    for d in dirs:
        yield from _walk_filtered(d)


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
    name = path.name.lower()
    stem = path.stem.lower()
    if stem.startswith("test_") or stem.endswith("_test"):
        return True
    if name.startswith("jest."):
        return True
    if any(name.endswith(sfx) for sfx in _TEST_SUFFIXES):
        return True
    # 'test' as a hyphen/underscore-separated component (e.g. stress-test-keys)
    stem_parts = set(stem.replace("_", "-").split("-"))
    if "test" in stem_parts or "tests" in stem_parts:
        return True
    parts_lower = {p.lower() for p in path.parts}
    return bool(parts_lower & _TEST_DIRS)


def is_generated_file(path: Path) -> bool:
    """Check if a file is generated / non-source (lock, locale, config).

    Args:
        path: File path to check.

    Returns:
        True if the file is auto-generated or non-source-code.
    """
    name = path.name.lower()
    if name in SKIP_FILES:
        return True
    parts = [p.lower() for p in path.parts]
    if "locales" in parts or "i18n" in parts or "translations" in parts or "messages" in parts:
        if path.suffix.lower() == ".json":
            return True
    return False


def _is_backup_dir(name: str) -> bool:
    """Check if directory name looks like a backup."""
    lower = name.lower()
    return any(lower.endswith(suffix) for suffix in _BACKUP_SUFFIXES)
