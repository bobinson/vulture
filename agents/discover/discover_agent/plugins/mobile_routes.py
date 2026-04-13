"""MobileRoutesPlugin — discover API endpoints from mobile app source code.

Extracts HTTP endpoints from Retrofit (Android), Alamofire/URLSession (iOS),
Flutter/Dart HTTP clients, deep links, and Firebase configurations.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import extract_urls_from_text

logger = logging.getLogger(__name__)

_MAX_MOBILE_FILES = 200


@register_plugin
class MobileRoutesPlugin(DiscoveryPlugin):
    """Discover API endpoints from mobile source code (Android, iOS, Flutter)."""

    name = "mobile_routes"
    priority = 23

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return bool(ctx.source_path)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        if not root.is_dir():
            return result

        scanned = 0
        for fpath in root.rglob("*"):
            if scanned >= _MAX_MOBILE_FILES or not fpath.is_file():
                continue
            extractors = _get_extractors(fpath)
            if not extractors:
                continue
            try:
                content = fpath.read_text(errors="replace")
            except Exception:
                continue
            for ext in extractors:
                ext(content, result)
            _extract_firebase(content, result)
            scanned += 1

        if result.endpoints or result.urls:
            logger.info(
                "MobileRoutes: found %d endpoints, %d URLs",
                len(result.endpoints), len(result.urls),
            )
        return result


def _get_extractors(fpath: Path) -> list:
    """Return the list of extractor functions for a mobile source file."""
    suffix = fpath.suffix.lower()
    name = fpath.name
    if suffix in (".java", ".kt"):
        return [_extract_retrofit]
    if suffix == ".swift":
        return [_extract_alamofire, _extract_urlsession]
    if suffix == ".dart":
        return [_extract_dart_http]
    if name == "AndroidManifest.xml":
        return [_extract_android_deeplinks]
    if name == "Info.plist":
        return [_extract_ios_deeplinks]
    return []


# --- Retrofit (Android) ---

_RETROFIT_RE = re.compile(
    r"""@(GET|POST|PUT|DELETE|PATCH|HEAD)\s*\(\s*["']([^"']+)["']""",
)


def _extract_retrofit(content: str, result: DiscoveryResult) -> None:
    for m in _RETROFIT_RE.finditer(content):
        path = m.group(2)
        if not path.startswith("/"):
            path = "/" + path
        result.endpoints.append(path)
    if _RETROFIT_RE.search(content):
        result.technologies.append("Retrofit")


# --- Alamofire (iOS) ---

_ALAMOFIRE_RE = re.compile(
    r"""(?:AF\.request|\.request)\s*\(\s*["']([^"']+)["']""",
)


def _extract_alamofire(content: str, result: DiscoveryResult) -> None:
    for m in _ALAMOFIRE_RE.finditer(content):
        url = m.group(1)
        if url.startswith("http"):
            result.urls.append(url)
        elif url.startswith("/"):
            result.endpoints.append(url)
    if _ALAMOFIRE_RE.search(content):
        result.technologies.append("Alamofire")


# --- URLSession (iOS) ---

_URLSESSION_RE = re.compile(
    r"""URL\s*\(\s*string:\s*["']([^"']+)["']""",
)


def _extract_urlsession(content: str, result: DiscoveryResult) -> None:
    for m in _URLSESSION_RE.finditer(content):
        url = m.group(1)
        if url.startswith("http"):
            result.urls.append(url)
        elif url.startswith("/"):
            result.endpoints.append(url)


# --- Flutter/Dart ---

_DART_HTTP_RE = re.compile(
    r"""(?:http\.(?:get|post|put|delete|patch)|Dio\(\)\.(?:get|post|put|delete|patch))\s*\(\s*["']([^"']+)["']""",
)
_DART_URI_RE = re.compile(
    r"""Uri\.parse\s*\(\s*["']([^"']+)["']""",
)


def _extract_dart_http(content: str, result: DiscoveryResult) -> None:
    for m in _DART_HTTP_RE.finditer(content):
        url = m.group(1)
        if url.startswith("http"):
            result.urls.append(url)
        elif url.startswith("/"):
            result.endpoints.append(url)
    for m in _DART_URI_RE.finditer(content):
        url = m.group(1)
        if url.startswith("http"):
            result.urls.append(url)
    if _DART_HTTP_RE.search(content) or _DART_URI_RE.search(content):
        result.technologies.append("Flutter")


# --- Android Deep Links ---

_ANDROID_SCHEME_RE = re.compile(
    r"""android:scheme\s*=\s*["']([^"']+)["']""",
)
_ANDROID_HOST_RE = re.compile(
    r"""android:host\s*=\s*["']([^"']+)["']""",
)


def _extract_android_deeplinks(content: str, result: DiscoveryResult) -> None:
    schemes = _ANDROID_SCHEME_RE.findall(content)
    hosts = _ANDROID_HOST_RE.findall(content)
    for scheme in schemes:
        for host in hosts:
            if scheme in ("http", "https"):
                result.urls.append(f"{scheme}://{host}")
            result.metadata.setdefault("deeplinks", []).append(f"{scheme}://{host}")


# --- iOS Deep Links ---

_IOS_SCHEME_RE = re.compile(
    r"""<string>([\w.+-]+)</string>""",
)


def _extract_ios_deeplinks(content: str, result: DiscoveryResult) -> None:
    if "CFBundleURLSchemes" in content:
        for m in _IOS_SCHEME_RE.finditer(content):
            scheme = m.group(1)
            if scheme not in ("String", "Array", "Dict"):
                result.metadata.setdefault("deeplinks", []).append(f"{scheme}://")


# --- Firebase ---

_FIREBASE_RE = re.compile(
    r"""([\w-]+\.firebaseio\.com|firestore\.googleapis\.com[^\s"']*)""",
)


def _extract_firebase(content: str, result: DiscoveryResult) -> None:
    for m in _FIREBASE_RE.finditer(content):
        url = m.group(1)
        if not url.startswith("http"):
            url = "https://" + url
        if url not in result.urls:
            result.urls.append(url)
            result.technologies.append("Firebase")
