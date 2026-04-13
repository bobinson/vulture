"""Shared utilities for discovery plugins — DRY helpers for network probing,
dependency detection, config parsing, and URL/port extraction.

All network functions use short timeouts (3-5s). All file-parsing functions
handle malformed input gracefully.
"""

import asyncio
import logging
import re
from pathlib import Path
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

import httpx

logger = logging.getLogger(__name__)

_DEFAULT_TCP_TIMEOUT = 3.0
_DEFAULT_HTTP_TIMEOUT = 5.0

# --- Port probing ---


async def probe_port(host: str, port: int, timeout: float = _DEFAULT_TCP_TIMEOUT) -> bool:
    """Check if a TCP port is open on *host*."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def probe_http_port(
    client: httpx.AsyncClient,
    base_url: str,
    port: int,
    path: str = "/",
    timeout: float = _DEFAULT_HTTP_TIMEOUT,
) -> httpx.Response | None:
    """Attempt an HTTP GET on *base_url* with a different *port*."""
    from urllib.parse import urlparse

    parsed = urlparse(base_url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or "localhost"
    url = f"{scheme}://{host}:{port}{path}"
    try:
        resp = await client.get(url, timeout=timeout)
        return resp
    except Exception:
        return None


# --- Dependency detection ---

_DEP_FILES: dict[str, str] = {
    "package.json": "node",
    "requirements.txt": "python",
    "Pipfile": "python",
    "go.mod": "go",
    "Cargo.toml": "rust",
    "Gemfile": "ruby",
    "composer.json": "php",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "pubspec.yaml": "dart",
}


_DEP_PARSERS: dict[str, object] = {}  # Populated after function defs


def detect_dependencies(root: Path) -> dict[str, list[str]]:
    """Scan common manifest files and return ``{ecosystem: [dep_names]}``."""
    deps: dict[str, list[str]] = {}
    for fname, eco in _DEP_FILES.items():
        fpath = root / fname
        if not fpath.is_file():
            continue
        try:
            text = fpath.read_text(errors="replace")
        except Exception:
            continue
        parser = _DEP_PARSERS.get(eco)
        if parser:
            deps.setdefault(eco, []).extend(parser(text))
    return deps


def has_dependency(root: Path, names: set[str]) -> bool:
    """Return True if any of *names* appears in dependency manifests."""
    deps = detect_dependencies(root)
    all_deps = {d.lower() for dlist in deps.values() for d in dlist}
    return bool(names & all_deps)


_NODE_DEP_RE = re.compile(r'"(@?[\w./-]+)"\s*:')


def _parse_node_deps(text: str) -> list[str]:
    return _NODE_DEP_RE.findall(text)


_PY_DEP_RE = re.compile(r"^([\w-]+)", re.MULTILINE)


def _parse_python_deps(text: str) -> list[str]:
    return [m.lower() for m in _PY_DEP_RE.findall(text)]


_GO_DEP_RE = re.compile(r"^\s+([\w./\-]+)", re.MULTILINE)


def _parse_go_deps(text: str) -> list[str]:
    return _GO_DEP_RE.findall(text)


_RUST_DEP_RE = re.compile(r"^\[dependencies\.([\w-]+)]", re.MULTILINE)
_RUST_DEP_INLINE = re.compile(r'^([\w-]+)\s*=', re.MULTILINE)


def _parse_rust_deps(text: str) -> list[str]:
    result = _RUST_DEP_RE.findall(text)
    in_deps = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[dependencies]":
            in_deps = True
            continue
        if stripped.startswith("[") and stripped != "[dependencies]":
            in_deps = False
        if in_deps:
            m = _RUST_DEP_INLINE.match(stripped)
            if m:
                result.append(m.group(1))
    return result


_RUBY_DEP_RE = re.compile(r"""gem\s+['"]([^'"]+)['"]""")


def _parse_ruby_deps(text: str) -> list[str]:
    return _RUBY_DEP_RE.findall(text)


def _parse_php_deps(text: str) -> list[str]:
    return _NODE_DEP_RE.findall(text)  # composer.json same format as package.json


_JAVA_DEP_RE = re.compile(r"<artifactId>([\w.-]+)</artifactId>")


def _parse_java_deps(text: str) -> list[str]:
    return _JAVA_DEP_RE.findall(text)


_DART_DEP_RE = re.compile(r"^\s{2}([\w_]+):", re.MULTILINE)


def _parse_dart_deps(text: str) -> list[str]:
    return _DART_DEP_RE.findall(text)


# Wire ecosystem → parser after all functions are defined
_DEP_PARSERS.update({
    "node": _parse_node_deps,
    "python": _parse_python_deps,
    "go": _parse_go_deps,
    "rust": _parse_rust_deps,
    "ruby": _parse_ruby_deps,
    "php": _parse_php_deps,
    "java": _parse_java_deps,
    "dart": _parse_dart_deps,
})


# --- Config parsing ---


def safe_yaml_load(content: str) -> dict | list | None:
    """Parse YAML, returning None on failure or if PyYAML is unavailable."""
    try:
        import yaml  # type: ignore[import-untyped]
        return yaml.safe_load(content)
    except Exception:
        return None


_MAX_XML_SIZE = 5_000_000  # 5 MB — reject oversized XML to prevent entity expansion


def safe_xml_parse(content: str) -> Element | None:
    """Parse XML, returning None on malformed or oversized input."""
    if not content or len(content) > _MAX_XML_SIZE:
        return None
    try:
        return ElementTree.fromstring(content)
    except Exception:
        return None


# --- URL / port extraction from text ---

_URL_RE = re.compile(r"https?://[^\s\"'`<>]+")
_PORT_RE = re.compile(r":(\d{2,5})(?:[/\s]|$)")


def extract_urls_from_text(text: str) -> list[str]:
    """Extract HTTP(S) URLs from arbitrary text."""
    return list(dict.fromkeys(_URL_RE.findall(text)))


def extract_ports_from_text(text: str) -> list[int]:
    """Extract port numbers from arbitrary text."""
    ports: list[int] = []
    for m in _PORT_RE.findall(text):
        try:
            p = int(m)
            if 1 <= p <= 65535:
                ports.append(p)
        except ValueError:
            pass
    return list(dict.fromkeys(ports))


# --- Generic endpoint probe ---


_SOURCE_EXTENSIONS = (".ts", ".js", ".mjs", ".cjs")


def read_source_file(root: Path, *names: str) -> str | None:
    """Find first matching file by name (tries .ts/.js/.mjs/.cjs extensions), read it.

    Checks ``root/`` and ``root/src/``. Returns content or ``None``.
    """
    search_dirs = [root, root / "src"]
    for name in names:
        for d in search_dirs:
            # Try exact name first
            candidate = d / name
            if candidate.is_file():
                try:
                    return candidate.read_text(errors="replace")
                except Exception:
                    continue
            # Try with extensions
            for ext in _SOURCE_EXTENSIONS:
                candidate = d / f"{name}{ext}"
                if candidate.is_file():
                    try:
                        return candidate.read_text(errors="replace")
                    except Exception:
                        continue
    return None


def find_files_by_name(root: Path, name: str, max_results: int = 50) -> list[Path]:
    """Walk tree for a specific filename. Capped at *max_results*.

    Uses os.walk instead of rglob to handle filenames containing glob
    special characters (e.g. ``[...nextauth].ts``).
    """
    import os

    results: list[Path] = []
    try:
        for dirpath, _dirs, files in os.walk(root):
            if name in files:
                results.append(Path(dirpath) / name)
                if len(results) >= max_results:
                    break
    except Exception:
        pass
    return results


async def probe_endpoint(
    client: httpx.AsyncClient,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | str | None = None,
    timeout: float = _DEFAULT_HTTP_TIMEOUT,
) -> tuple[bool, httpx.Response | None]:
    """Probe an endpoint, returning ``(reachable, response|None)``."""
    try:
        kwargs: dict = {"timeout": timeout}
        if headers:
            kwargs["headers"] = headers
        if body is not None:
            kwargs["content"] = body if isinstance(body, bytes) else body.encode()
        resp = await client.request(method, url, **kwargs)
        return True, resp
    except Exception:
        return False, None


# --- WebSocket URL conversion ---


def to_ws_url(http_url: str, path: str = "") -> str:
    """Convert an HTTP URL to its WebSocket equivalent.

    http:// → ws://, https:// → wss://
    """
    from urllib.parse import urlparse

    parsed = urlparse(http_url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    host = parsed.hostname or ""
    port_part = f":{parsed.port}" if parsed.port else ""
    ws_path = path or parsed.path or ""
    return f"{ws_scheme}://{host}{port_part}{ws_path}"
