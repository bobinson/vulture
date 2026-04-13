"""WebhookReceiversPlugin — detect webhook receiver endpoints.

Two-pass scanning: (1) file paths containing webhook/hook/callback,
(2) content matching known webhook verification signatures (Stripe,
GitHub, Slack, Telegram, Twilio, generic HMAC).
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin

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
_EXCLUDED_DIRS = {"node_modules", "dist", "build", ".next", ".git", "__pycache__"}


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
        for fpath in pass1_files:
            _process_file(fpath, root, receivers, seen_paths, tech_set)

        _scan_remaining(root, pass1_files, receivers, seen_paths, tech_set)
        _build_result(result, receivers, seen_paths, tech_set)
        return result


def _scan_remaining(
    root: Path, pass1_files: set[Path],
    receivers: list[dict], seen_paths: set[str], tech_set: set[str],
) -> None:
    """Pass 2: scan remaining files for webhook signatures."""
    scanned = 0
    for fpath in root.rglob("*"):
        if scanned >= _MAX_FILES:
            break
        if not fpath.is_file() or fpath.suffix not in _JS_EXTENSIONS:
            continue
        if _is_excluded(fpath) or fpath in pass1_files:
            continue
        scanned += 1
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
    results: set[Path] = set()
    count = 0
    for fpath in root.rglob("*"):
        if count >= _MAX_FILES:
            break
        if not fpath.is_file() or fpath.suffix not in _JS_EXTENSIONS:
            continue
        if _is_excluded(fpath):
            continue
        rel = str(fpath.relative_to(root))
        if _PATH_KEYWORDS.search(rel):
            results.add(fpath)
        count += 1
    return results


def _is_excluded(fpath: Path) -> bool:
    """Skip vendor/build directories."""
    return any(p in _EXCLUDED_DIRS for p in fpath.parts)


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
            if path.startswith("/api/") or path.startswith("/hook"):
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
