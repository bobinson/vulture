"""WebhookReceiversPlugin — detect webhook receiver endpoints.

Two-pass scanning: (1) file paths containing webhook/hook/callback,
(2) content matching known webhook verification signatures (Stripe,
GitHub, Slack, Telegram, Twilio, generic HMAC).
"""

import logging
import re
from collections.abc import Iterator
from itertools import islice
from pathlib import Path

from shared.discovery.plugin_base import (
    DiscoveryContext,
    DiscoveryPlugin,
    DiscoveryResult,
    register_plugin,
)
from shared.tools.file_scanner import tree_files

logger = logging.getLogger(__name__)

_MAX_FILES = 200
_JS_EXTENSIONS = {".ts", ".js", ".mjs", ".cjs", ".py", ".go", ".rb", ".php", ".java"}
_PATH_KEYWORDS = re.compile(r"(?:webhook|hook|callback)", re.IGNORECASE)

_WEBHOOK_SIGNATURES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"stripe\.webhooks\.constructEvent"), "Stripe"),
    (re.compile(r"x-hub-signature", re.IGNORECASE), "GitHub"),
    (re.compile(r"url_verification|challenge.*token"), "Slack"),
    (re.compile(r"webhookCallback|grammy|telegraf", re.IGNORECASE), "Telegram"),
    (re.compile(r"X-Twilio-Signature", re.IGNORECASE), "Twilio"),
    (re.compile(r"crypto\.createHmac.*sha256"), "HMAC-Webhook"),
    (re.compile(r"timingSafeEqual"), "HMAC-Webhook"),
]

_ROUTE_IN_FILE_RE = re.compile(r"""['"](/[\w/\-:.{}]+)['"]""")


@register_plugin
class WebhookReceiversPlugin(DiscoveryPlugin):
    """Detect webhook receiver endpoints by file path and content signatures."""

    name = "webhook_receivers"
    priority = 25

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return bool(ctx.source_path)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        if not root.is_dir():
            return result

        receivers: list[dict] = []
        seen_paths: set[str] = set()
        tech_set: set[str] = set()

        pass1_files = _find_webhook_files(root)
        # In a fixed order: which file first claims a shared path must not
        # depend on a set's iteration order.
        for fpath in sorted(pass1_files):
            _process_file(fpath, root, receivers, seen_paths, tech_set)

        _scan_remaining(root, pass1_files, receivers, seen_paths, tech_set)
        _build_result(result, receivers, seen_paths, tech_set)
        return result


def _scan_remaining(
    root: Path, pass1_files: set[Path],
    receivers: list[dict], seen_paths: set[str], tech_set: set[str],
) -> None:
    """Pass 2: scan remaining files for webhook signatures."""
    remaining = (fpath for fpath in _source_files(root) if fpath not in pass1_files)
    for fpath in islice(remaining, _MAX_FILES):
        _process_file(fpath, root, receivers, seen_paths, tech_set)


def _build_result(
    result: DiscoveryResult, receivers: list[dict],
    seen_paths: set[str], tech_set: set[str],
) -> None:
    """Assemble final result from collected data."""
    for path in seen_paths:
        result.endpoints.append(path)
    for tech in sorted(tech_set):
        result.technologies.append(f"Webhook:{tech}")
    if receivers:
        result.metadata["webhook_receivers"] = receivers
    if result.endpoints:
        logger.info("WebhookReceivers: found %d endpoints", len(result.endpoints))


def _find_webhook_files(root: Path) -> set[Path]:
    """Find files with webhook/hook/callback in their path."""
    return {
        fpath for fpath in islice(_source_files(root), _MAX_FILES)
        if _PATH_KEYWORDS.search(str(fpath.relative_to(root)))
    }


def _source_files(root: Path) -> Iterator[Path]:
    """The walked source files of the kinds a webhook receiver is written in."""
    return (fpath for fpath in tree_files(root) if fpath.suffix in _JS_EXTENSIONS)


def _process_file(
    fpath: Path, root: Path,
    receivers: list[dict], seen_paths: set[str], tech_set: set[str],
) -> None:
    """Scan a file for webhook signatures and extract route paths."""
    try:
        content = fpath.read_text(errors="replace")
    except Exception:
        return

    platforms = _detect_platforms(content)
    if not platforms:
        rel = str(fpath.relative_to(root))
        if _PATH_KEYWORDS.search(rel):
            platforms = ["Generic"]
        else:
            return

    rel = str(fpath.relative_to(root))
    paths = _extract_paths(content)
    webhook_path = paths[0] if paths else _infer_path_from_file(rel)

    for platform in platforms:
        tech_set.add(platform)
        if webhook_path and webhook_path not in seen_paths:
            seen_paths.add(webhook_path)
            receivers.append({"path": webhook_path, "platform": platform, "file": rel})


def _detect_platforms(content: str) -> list[str]:
    """Match content against webhook signature table."""
    platforms: list[str] = []
    seen: set[str] = set()
    for pattern, platform in _WEBHOOK_SIGNATURES:
        if platform not in seen and pattern.search(content):
            platforms.append(platform)
            seen.add(platform)
    return platforms


def _extract_paths(content: str) -> list[str]:
    """Extract route-like paths from file content."""
    paths: list[str] = []
    for m in _ROUTE_IN_FILE_RE.finditer(content):
        path = m.group(1)
        if path.startswith("/") and "webhook" in path.lower():
            paths.append(path)
    if not paths:
        for m in _ROUTE_IN_FILE_RE.finditer(content):
            path = m.group(1)
            if path.startswith(("/api/", "/hook")):
                paths.append(path)
                break
    return paths


def _infer_path_from_file(rel_path: str) -> str:
    """Infer a webhook path from the file's relative path."""
    parts = Path(rel_path).with_suffix("").parts
    cleaned = [p for p in parts if p not in ("src", "pages", "app", "api")]
    if cleaned:
        return "/api/" + "/".join(cleaned)
    return ""
