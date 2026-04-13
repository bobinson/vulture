"""SOAPWSDLPlugin — discover SOAP/WSDL endpoints via probing and source parsing.

Probes common WSDL paths, parses .wsdl files from source, and detects SOAP
from Content-Type headers and XML response bodies.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import has_dependency, probe_endpoint, safe_xml_parse

logger = logging.getLogger(__name__)

_WSDL_PATHS = [
    "/?wsdl",
    "/service?wsdl",
    "/services?wsdl",
    "/ws?wsdl",
    "/wsdl",
    "/service.wsdl",
    "/soap",
    "/services",
]

_SOAP_DEPS = {
    "zeep", "suds", "suds-community", "suds-jurko",
    "javax.xml.ws", "system.servicemodel",
    "soap", "node-soap", "strong-soap",
}


@register_plugin
class SOAPWSDLPlugin(DiscoveryPlugin):
    """Discover SOAP/WSDL endpoints via HTTP probing and source file parsing."""

    name = "soap_wsdl"
    priority = 35

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        base = ctx.staging_url.rstrip("/")
        already_found = set(ctx.site.api_endpoints)

        # 1. Probe WSDL paths live
        await _probe_wsdl_paths(ctx.http_client, base, already_found, result)

        # 2. Parse .wsdl files from source
        if ctx.source_path:
            _scan_wsdl_files(Path(ctx.source_path), result)

        # 3. Detect SOAP library dependencies
        if ctx.source_path:
            root = Path(ctx.source_path)
            if has_dependency(root, _SOAP_DEPS):
                if "SOAP" not in result.technologies:
                    result.technologies.append("SOAP")

        return result


async def _probe_wsdl_paths(
    client, base: str, already_found: set[str], result: DiscoveryResult,
) -> None:
    """Probe common WSDL paths and detect SOAP from responses."""
    for path in _WSDL_PATHS:
        if path in already_found:
            continue
        ok, resp = await probe_endpoint(client, f"{base}{path}", timeout=5.0)
        if not ok or resp is None or resp.status_code >= 400:
            continue
        if _is_wsdl_response(resp):
            result.endpoints.append(path)
            result.urls.append(path)
            result.technologies.append("SOAP/WSDL")
            _parse_wsdl_xml(resp.text[:2000], result)
            logger.info("SOAP/WSDL endpoint found: %s", path)
            return  # One WSDL spec is enough


_WSDL_BODY_MARKERS = ("<wsdl:definitions", "<definitions", "xmlns:wsdl")


def _is_wsdl_response(resp) -> bool:
    """Check if an HTTP response looks like a SOAP/WSDL response."""
    ct = resp.headers.get("content-type", "")
    if "text/xml" in ct or "application/soap+xml" in ct:
        return True
    body = resp.text[:2000]
    return any(marker in body for marker in _WSDL_BODY_MARKERS)


def _parse_wsdl_xml(xml_text: str, result: DiscoveryResult) -> None:
    """Extract service addresses and operation names from WSDL XML."""
    root = safe_xml_parse(xml_text)
    if root is None:
        return

    # Extract <service><port><address location="..."/>
    for elem in root.iter():
        tag = _local_tag(elem.tag)
        if tag == "address":
            location = elem.get("location", "")
            if location:
                result.urls.append(location)
                result.metadata.setdefault("soap_endpoints", []).append(location)
        elif tag == "operation":
            name = elem.get("name", "")
            if name:
                result.metadata.setdefault("soap_operations", []).append(name)


def _scan_wsdl_files(root: Path, result: DiscoveryResult) -> None:
    """Scan source for .wsdl files and parse them."""
    count = 0
    for fpath in root.rglob("*.wsdl"):
        if count >= 10:
            break
        try:
            content = fpath.read_text(errors="replace")
            _parse_wsdl_xml(content, result)
            result.technologies.append("SOAP/WSDL")
            count += 1
        except Exception:
            pass


def _local_tag(tag: str) -> str:
    """Strip XML namespace prefix from a tag."""
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag
