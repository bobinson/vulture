"""HTTP client for calling the discover agent via SSE.

Prove agent delegates all discovery to the discover agent over HTTP,
eliminating the circular dependency on prove_agent.plugins.
"""

import json
import logging
import os
from uuid import uuid4

import httpx

from shared.discovery.sitemap import SiteMap

logger = logging.getLogger(__name__)

_DISCOVER_URL = os.environ.get("VULTURE_DISCOVER_URL", "http://agent-discover:28008")
_TIMEOUT = 300.0  # Discovery can take up to 5 minutes


def call_discover(
    target_url: str,
    *,
    source_path: str = "",
    no_cache: bool = False,
    schemas: dict | None = None,
) -> tuple[SiteMap | None, str, list[dict]]:
    """Call discover agent via HTTP SSE.

    Returns:
        (site_map, learnings_context, findings)
    """
    payload = {
        "run_id": f"discover-{uuid4().hex[:8]}",
        "source_path": source_path,
        "config": {
            "target_url": target_url,
            "source_path": source_path,
            "no_cache": no_cache,
            "schemas": schemas or {},
        },
        "prior_findings": [],
    }

    site_map: SiteMap | None = None
    learnings_ctx = ""
    findings: list[dict] = []

    try:
        with httpx.Client(timeout=_TIMEOUT) as client:
            with client.stream(
                "POST", f"{_DISCOVER_URL}/run", json=payload,
            ) as resp:
                event_type = ""
                for line in resp.iter_lines():
                    if not line:
                        # Blank line = SSE event delimiter
                        event_type = ""
                    elif line.startswith("event: "):
                        event_type = line[7:].strip()
                    elif line.startswith("data: ") and event_type:
                        try:
                            data = json.loads(line[6:])
                        except json.JSONDecodeError:
                            continue
                        if event_type == "discover_result":
                            site_json = data.get("site_map_json", "")
                            if site_json:
                                site_map = SiteMap.from_json(site_json)
                            learnings_ctx = data.get("learnings_context", "")
                        elif event_type == "finding":
                            findings.append(data)
    except Exception as exc:
        logger.warning("Discover agent call failed: %s", exc)

    return site_map, learnings_ctx, findings
