"""SiteMap dataclass — discovered site structure for a target URL."""

from __future__ import annotations

import json as _json
from dataclasses import asdict, dataclass, field


@dataclass
class SiteMap:
    """Discovered site structure for a staging URL."""

    urls: list[str] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    technologies: list[str] = field(default_factory=list)
    disallowed_paths: list[str] = field(default_factory=list)

    def summary(self, max_urls: int = 40) -> str:
        """Compact text summary for LLM context, prioritizing API endpoints."""
        parts = []
        if self.technologies:
            parts.append("Technologies: " + ", ".join(self.technologies))
        if self.api_endpoints:
            parts.append(
                "API endpoints (backend, use these for verification):\n"
                + "\n".join(f"  {e}" for e in self.api_endpoints[:30])
            )
        if self.forms:
            form_lines = []
            for f in self.forms[:10]:
                inputs = ", ".join(f.get("inputs", [])) or "none"
                form_lines.append(
                    f"  {f['method']} {f['action']} inputs=[{inputs}]"
                )
            parts.append("Forms (submit targets):\n" + "\n".join(form_lines))
        if self.disallowed_paths:
            parts.append("Disallowed (robots.txt):\n" + "\n".join(
                f"  {p}" for p in self.disallowed_paths[:15]
            ))
        if self.headers:
            parts.append("Response headers:\n" + "\n".join(
                f"  {k}: {v}" for k, v in self.headers.items()
            ))
        page_urls = [u for u in self.urls if u not in set(self.api_endpoints)]
        if page_urls:
            parts.append("Other pages:\n" + "\n".join(
                f"  {u}" for u in page_urls[:max_urls]
            ))
        return "\n\n".join(parts) if parts else "No site structure discovered."

    def merge(self, other: SiteMap) -> int:
        """Merge another SiteMap into this one. Returns count of new items added."""
        before = len(self.urls) + len(self.api_endpoints) + len(self.forms)

        existing_urls = set(self.urls)
        for u in other.urls:
            if u not in existing_urls:
                self.urls.append(u)

        existing_api = set(self.api_endpoints)
        for e in other.api_endpoints:
            if e not in existing_api:
                self.api_endpoints.append(e)

        existing_forms = {f.get("action", "") + "|" + f.get("method", "") for f in self.forms}
        for f in other.forms:
            key = f.get("action", "") + "|" + f.get("method", "")
            if key not in existing_forms:
                self.forms.append(f)

        existing_disallowed = set(self.disallowed_paths)
        for p in other.disallowed_paths:
            if p not in existing_disallowed:
                self.disallowed_paths.append(p)

        existing_tech = set(self.technologies)
        for t in other.technologies:
            if t not in existing_tech:
                self.technologies.append(t)

        self.headers.update(other.headers)

        after = len(self.urls) + len(self.api_endpoints) + len(self.forms)
        return after - before

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return _json.dumps(asdict(self), indent=2)

    @classmethod
    def from_json(cls, data: str) -> SiteMap:
        """Deserialize from JSON string."""
        d = _json.loads(data)
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})

    def deduplicate(self) -> None:
        """Remove duplicates and sort all lists."""
        self.urls = sorted(set(self.urls))
        self.api_endpoints = sorted(set(self.api_endpoints))
        self.disallowed_paths = sorted(set(self.disallowed_paths))
        self.technologies = sorted(set(self.technologies))
        seen_forms: set[str] = set()
        unique_forms = []
        for f in self.forms:
            key = f.get("action", "") + "|" + f.get("method", "")
            if key not in seen_forms:
                seen_forms.add(key)
                unique_forms.append(f)
        self.forms = unique_forms
