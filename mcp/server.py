"""Vulture MCP Server — exposes audit findings to MCP-compatible agent harnesses."""

import asyncio
import os
import re
import stat
import sys
from collections import deque
from time import monotonic

import httpx
from mcp.server.fastmcp import Context, FastMCP

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

_REDACT_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(
        r'(?i)(password|passwd|secret|token|api_key|apikey|auth)\s*[:=]\s*["\'][^"\']{4,}["\']'
    ), r'\1=***'),
    (re.compile(r'(?i)(Bearer\s+)\S{20,}'), r'\1***'),
    (re.compile(r'(?i)(?:ghp_|gho_|github_pat_|sk-|sk-proj-|vk_|glpat-|AKIA)[A-Za-z0-9\-_]{10,}'), '***'),
    (re.compile(r'(?i)postgres(?:ql)?://[^@\s]+@'), 'postgres://***@'),
    (re.compile(r'(?i)mongodb(?:\+srv)?://[^@\s]+@'), 'mongodb://***@'),
]


def redact_secrets(text: str | None) -> str:
    """Strip secrets from text using regex patterns. Returns empty string for None/empty."""
    if not text:
        return ""
    for pattern, replacement in _REDACT_RULES:
        text = pattern.sub(replacement, text)
    return text


# ---------------------------------------------------------------------------
# Vulture API Client
# ---------------------------------------------------------------------------


class RateLimitExceeded(Exception):
    """No request slot was free, or none freed up within a waiting call's bound."""


class VultureClient:
    """Async HTTP client for Vulture API. Holds credentials; never exposes them."""

    # How long a waiting call may wait for a slot. An uncontended slot frees
    # within one 1s window, so only a caller that keeps half the window busy
    # for this long makes a waiting call give up.
    _WAIT_MAX_SEC = 2.0

    def __init__(self, base_url: str, api_key: str | None, rate_limit: int = 10):
        self._base = base_url.rstrip("/")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._client = httpx.AsyncClient(
            base_url=self._base,
            headers=headers,
            timeout=30.0,
            verify=True,
        )
        self._rate_limit = rate_limit
        self._timestamps: deque[float] = deque()
        self._rate_lock = asyncio.Lock()

    def _take_slot(self, ceiling: int) -> float | None:
        """Record a request if fewer than `ceiling` slots are in use (None);
        otherwise return the seconds until the oldest slot frees."""
        now = monotonic()
        while self._timestamps and now - self._timestamps[0] > 1.0:
            self._timestamps.popleft()
        if len(self._timestamps) < ceiling:
            self._timestamps.append(now)
            return None
        return 1.0 - (now - self._timestamps[0])

    async def _enforce_rate_limit(self, wait: bool = False) -> None:
        """Take a request slot. With wait=True, sleep for the next free slot
        instead of raising — for fan-out a single tool call makes on its own.
        A waiting caller takes a slot only while fewer than half are in use
        (all of them at rate_limit=1), so its fan-out leaves the rest to
        concurrent tool calls; it raises RateLimitExceeded if no slot frees
        up within _WAIT_MAX_SEC, so busy callers cannot make it hang."""
        ceiling, budget = ((max(self._rate_limit // 2, 1), self._WAIT_MAX_SEC) if wait
                           else (self._rate_limit, 0.0))
        give_up = monotonic() + budget
        while True:
            async with self._rate_lock:
                delay = self._take_slot(ceiling)
            if delay is None:
                return
            if monotonic() + delay > give_up:
                raise RateLimitExceeded(f"Rate limit exceeded ({self._rate_limit} req/s)")
            await asyncio.sleep(max(delay, 0.0))

    async def _request(self, method: str, path: str, wait: bool = False, **kwargs) -> dict | list:
        await self._enforce_rate_limit(wait)
        resp = await self._client.request(method, path, **kwargs)
        if resp.status_code >= 400:
            safe_body = redact_secrets(resp.text[:200])
            raise Exception(f"Vulture API error ({resp.status_code}): {safe_body}")
        return resp.json()

    async def list_audits(self, limit: int = 10, status: str | None = None) -> list:
        params: dict = {"limit": limit}
        if status:
            params["status"] = status
        return await self._request("GET", "/api/audits", params=params)

    async def get_audit(self, audit_id: str, wait: bool = False, params: dict | None = None) -> dict:
        return await self._request("GET", f"/api/audits/{audit_id}", wait=wait, params=params)

    async def get_comparison(self, audit_id: str) -> dict:
        return await self._request("GET", f"/api/audits/{audit_id}/comparison")

    async def search_memories(self, query: str, limit: int = 20) -> list:
        return await self._request("GET", "/api/memories/search", params={"q": query, "limit": limit})

    async def update_lineage(self, lineage_id: str, status: str, notes: str = "") -> dict:
        return await self._request("PATCH", f"/api/lineage/{lineage_id}", json={"status": status, "notes": notes})

    async def get_audit_lineage(self, audit_id: str) -> list:
        return await self._request("GET", f"/api/audits/{audit_id}/lineage")

    async def get_masked_values(self, audit_id: str, finding_id: str) -> dict:
        return await self._request("GET", f"/api/audits/{audit_id}/findings/{finding_id}/masked")

    @property
    def base_url(self) -> str:
        return self._base

    async def close(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# MCP Server + helpers
# ---------------------------------------------------------------------------

mcp = FastMCP("vulture-mcp")

_client: VultureClient | None = None
_client_lock = asyncio.Lock()

_VALID_STATUSES = {"open", "in_progress", "resolved", "false_positive", "accepted_risk", "fixed"}


def _read_token_file() -> str | None:
    """Read VULTURE_API_KEY from a token file when env vars are stripped.

    Some MCP hosts (e.g. Claude Desktop) drop *_KEY / *_TOKEN env vars from
    subprocess environments. The fallback path is `~/.config/vulture/mcp_token`,
    overridable via $VULTURE_MCP_TOKEN_FILE. Returns None when the file is
    missing, empty, or unreadable. Warns on stderr when the file is
    world/group-readable since the token is a secret and should be 0600.
    """
    path = os.environ.get(
        "VULTURE_MCP_TOKEN_FILE",
        os.path.expanduser("~/.config/vulture/mcp_token"),
    )
    try:
        st = os.stat(path)
    except OSError:
        return None
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        sys.stderr.write(
            f"vulture-mcp: warning: token file {path} has group/world permissions; "
            f"recommend `chmod 0600 {path}`\n"
        )
    try:
        with open(path, "r", encoding="utf-8") as f:
            token = f.read().strip()
    except OSError:
        return None
    return token or None

_SENSITIVE_FIELDS = ("code_snippet", "description", "recommendation", "content", "remediation_notes")


async def _get_client() -> VultureClient:
    global _client
    if _client is not None:
        return _client
    async with _client_lock:
        if _client is not None:
            return _client
        url = os.environ.get("VULTURE_URL", "")
        if not url:
            raise ValueError("VULTURE_URL environment variable is required")
        key = os.environ.get("VULTURE_API_KEY")
        if not key:
            key = _read_token_file()
        rate = int(os.environ.get("VULTURE_MCP_RATE_LIMIT", "10"))
        os.environ.setdefault("HTTPX_LOG_LEVEL", "warn")
        _client = VultureClient(url, key, rate_limit=rate)
    return _client


def _allow_write() -> bool:
    return os.environ.get("VULTURE_MCP_ALLOW_WRITE", "false").lower() == "true"


def _redact_record(f: dict) -> dict:
    """Return a copy with sensitive fields redacted."""
    out = dict(f)
    for key in _SENSITIVE_FIELDS:
        if key in out and out[key]:
            out[key] = redact_secrets(out[key])
    out.pop("webhook_url", None)
    return out


# Compliance frameworks a finding can be labelled with (feature 0096), each with
# the shape of its category ids, and the shape of an edition. Matches the
# backend's own mapping validation.
_FRAMEWORK_CATEGORY_IDS: dict[str, re.Pattern] = {"owasp": re.compile(r"^A\d{2}$")}
_EDITION_PATTERN = re.compile(r"^\d{4}$")


def _normalize_framework_filter(
    framework: str | None, category: str | None, edition: str | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Validate a framework filter. With a framework, `category` is that
    framework's category id (normalised, e.g. "a07" -> "A07") and `edition`
    narrows it to one edition; without one, category is returned untouched and
    keeps its literal meaning, and an edition is an error."""
    if framework is None:
        if edition is not None:
            raise ValueError('edition needs a framework (e.g. framework="owasp")')
        return None, category, None
    fw = _normalize_framework(framework)
    return fw, _normalize_category(fw, category), _normalize_edition(edition)


def _normalize_framework(framework: str) -> str:
    fw = framework.strip().lower()
    if fw not in _FRAMEWORK_CATEGORY_IDS:
        valid = ", ".join(sorted(_FRAMEWORK_CATEGORY_IDS))
        raise ValueError(f"Unknown framework '{framework}'. Valid: {valid}")
    return fw


def _normalize_category(fw: str, category: str | None) -> str | None:
    if category is None:
        return None
    cat = category.strip().upper()
    if not _FRAMEWORK_CATEGORY_IDS[fw].match(cat):
        raise ValueError(f"Invalid {fw} category '{category}': expected an id like A07")
    return cat


def _normalize_edition(edition: str | None) -> str | None:
    if edition is None:
        return None
    ed = edition.strip()
    if not _EDITION_PATTERN.match(ed):
        raise ValueError(f"Invalid edition '{edition}': expected a year like 2025")
    return ed


# Where a pre-0096 OWASP copy row keeps the category id it stood for: its
# check_id ("owasp.A07.cwe-798") and its category slug ("A07-authentication-failures").
_LEGACY_OWASP_ID_FIELDS: tuple[tuple[str, re.Pattern], ...] = (
    ("check_id", re.compile(r"^owasp\.(A\d{2})\.")),
    ("category", re.compile(r"^(A\d{2})-")),
)

# The edition a pre-0096 OWASP row's category slug names. Those rows were
# written from the 2021 and 2025 tables only, so this is a closed, historical
# set: a slug found in just one of them names that edition. A slug both share
# (A01-broken-access-control), or a row with no slug, names no edition.
_LEGACY_OWASP_SLUG_EDITIONS: dict[str, str] = {
    "A02-cryptographic-failures": "2021",
    "A03-injection": "2021",
    "A04-insecure-design": "2021",
    "A05-security-misconfiguration": "2021",
    "A06-vulnerable-and-outdated-components": "2021",
    "A07-identification-and-authentication-failures": "2021",
    "A08-software-and-data-integrity-failures": "2021",
    "A09-security-logging-and-monitoring-failures": "2021",
    "A10-ssrf": "2021",
    "A02-security-misconfiguration": "2025",
    "A03-software-supply-chain-failures": "2025",
    "A04-cryptographic-failures": "2025",
    "A05-injection": "2025",
    "A06-insecure-design": "2025",
    "A07-authentication-failures": "2025",
    "A08-software-or-data-integrity-failures": "2025",
    "A09-security-logging-and-alerting-failures": "2025",
    "A10-mishandling-of-exceptional-conditions": "2025",
}


def _legacy_owasp_labels(finding: dict) -> list[dict]:
    """The OWASP label a pre-0096 OWASP agent row stood for, read from the
    fields the backend persists, marked `legacy`. Empty for any other row. Its
    edition is "" when the row does not say, so it matches no edition filter."""
    category_id = _legacy_owasp_id(finding) if finding.get("agent_type") == "owasp" else None
    if not category_id:
        return []
    edition = _LEGACY_OWASP_SLUG_EDITIONS.get(finding.get("category") or "", "")
    return [{"framework": "owasp", "edition": edition, "category_id": category_id,
             "category_name": "", "legacy": True}]


def _legacy_owasp_id(finding: dict) -> str | None:
    matches = (p.match(finding.get(field) or "") for field, p in _LEGACY_OWASP_ID_FIELDS)
    return next((m.group(1) for m in matches if m), None)


def _framework_labels(finding: dict) -> list[dict]:
    """A finding's compliance labels, plus the label a pre-0096 OWASP copy row
    stood for (such a row carries no labels of its own)."""
    return list(finding.get("compliance_labels") or []) + _legacy_owasp_labels(finding)


def _with_legacy_labels(finding: dict) -> dict:
    """A pre-0096 OWASP row with the label it matched on made visible, so a
    framework-filtered result carries `compliance_labels` on every record."""
    return dict(finding, compliance_labels=_framework_labels(finding)) if _legacy_owasp_labels(finding) else finding


def _framework_output(records: list[dict], framework: str | None) -> list[dict]:
    return [_with_legacy_labels(r) for r in records] if framework else records


def _labelled(framework: str, category: str | None, edition: str | None):
    def match(f: dict) -> bool:
        return any(
            lb.get("framework") == framework
            and category in (None, lb.get("category_id"))
            and edition in (None, lb.get("edition"))
            for lb in _framework_labels(f)
        )
    return match


def _field_is(field: str, value: str | None):
    return (lambda f: f.get(field) == value) if value else None


def _category_pred(category: str | None, framework: str | None, edition: str | None):
    return _labelled(framework, category, edition) if framework else _field_is("category", category)


def _active(*preds):
    return [p for p in preds if p]


# Feature 0074: the provenance filter takes the vocabulary the findings API and
# the UI take. An exact value matches `provenance` literally; "llm_family" and
# "both" are the two family values. ONE family rule, the same as the backend's
# isLLMProvenance and the agents' _is_deterministic: a tier is a string,
# trimmed (Go's whitespace set, GO_SPACE) and lower-cased; a blank tier is no tier; a tier starting with "llm"
# is the LLM family, any other tier the skill family. A GROUPING provenance
# (catalog_rollup) names the rollup that grouped the leaves, not a tier that
# detected anything, so as an origin it is neither family (C11).
_SKILL_FAMILY, _LLM_FAMILY = 1, 2
_BOTH_FAMILIES = _SKILL_FAMILY | _LLM_FAMILY
_GROUPING_PROVENANCES = frozenset({"catalog_rollup"})

# T1: the ONE whitespace set every runtime trims a tier with, exactly Go's
# unicode.IsSpace (what strings.TrimSpace strips). Bare str.strip() also strips
# U+001C-U+001F, which Go keeps; U+FEFF is whitespace nowhere.
GO_SPACE = ("\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005"
            "\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000")


def _tier(value) -> str:
    return value.strip(GO_SPACE).lower() if isinstance(value, str) else ""


def _is_llm_tier(tier: str) -> bool:
    return tier.startswith("llm")


def _tier_family(value) -> int:
    """The family bit of one origin: 0 for no tier or a grouping provenance."""
    tier = _tier(value)
    if not tier or tier in _GROUPING_PROVENANCES:
        return 0
    return _LLM_FAMILY if _is_llm_tier(tier) else _SKILL_FAMILY


def _provenance_origins(finding: dict) -> list:
    """validation.provenance_origins when it is a list, else nothing: a
    malformed value (string, object, null, absent) is never an error."""
    validation = finding.get("validation")
    origins = validation.get("provenance_origins") if isinstance(validation, dict) else None
    return origins if isinstance(origins, list) else []


def _is_llm_family(finding: dict) -> bool:
    return _is_llm_tier(_tier(finding.get("provenance")))


def _spans_both_families(finding: dict) -> bool:
    """True when the rows deduplicated into this one came from a skill-family
    tier AND an LLM-family tier."""
    seen = 0
    for origin in _provenance_origins(finding):
        seen |= _tier_family(origin)
    return seen == _BOTH_FAMILIES


def _origins_recorded(audit: dict, findings: list[dict]) -> bool:
    """Whether the audit's findings record provenance_origins at all. The API's
    origins_recorded flag wins; an older backend sends none, so any row whose
    validation carries the provenance_origins key proves the record exists."""
    flag = audit.get("origins_recorded")
    if isinstance(flag, bool):
        return flag
    return any(_records_origins(f) for f in findings)


def _records_origins(finding: dict) -> bool:
    """The key's presence, whatever its value: the backend's markOriginsRecorded rule."""
    validation = finding.get("validation")
    return isinstance(validation, dict) and "provenance_origins" in validation


_ORIGINS_NOT_RECORDED_NOTE = (
    "This audit's findings record no provenance_origins (the audit predates "
    "tier-origin recording), so an empty \"both\" result means not recorded, "
    "not never corroborated.")


def _both_marker(provenance: str | None, audit: dict) -> dict:
    """#35: qualify a "both" result with whether origins were recorded."""
    if provenance != "both":
        return {}
    recorded = _origins_recorded(audit, audit.get("findings") or [])
    return {"origins_recorded": True} if recorded else {
        "origins_recorded": False, "note": _ORIGINS_NOT_RECORDED_NOTE}


_PROVENANCE_FAMILY_PREDS = {"llm_family": _is_llm_family, "both": _spans_both_families}


def _provenance_pred(provenance: str | None):
    """The filter value is exact and case-sensitive: a family word selects its
    family, any other value matches `provenance` literally."""
    return _PROVENANCE_FAMILY_PREDS.get(provenance) or _field_is("provenance", provenance)


def _filter_findings(
    findings: list[dict],
    severity: str | None,
    category: str | None,
    agent_type: str | None,
    framework: str | None = None,
    edition: str | None = None,
    provenance: str | None = None,
) -> list[dict]:
    """Filter findings by optional criteria. Extracted to keep tool CC < 5.

    agent_type is always literal. With a framework, category and edition
    filter that framework's labels; without one, category is the finding's own.
    provenance is an exact value or a family word (see _provenance_pred)."""
    preds = _active(_field_is("severity", severity), _field_is("agent_type", agent_type),
                    _category_pred(category, framework, edition), _provenance_pred(provenance))
    return [f for f in findings if all(p(f) for p in preds)]


# Distinct audits one framework-filtered search may fetch to resolve labels.
# Each lookup downloads a whole audit, so the fan-out is bounded.
_LABEL_LOOKUP_MAX_AUDITS = 10


async def _audit_label_map(client: "VultureClient", audit_id: str) -> dict[str, list[dict]]:
    """category -> compliance labels for one audit. A label is a pure function
    of the audit's mapping and the finding's category, so any labelled finding
    of a category speaks for all of them. Empty on failure, so a record whose
    audit is unreadable simply matches no framework filter. A busy client
    (RateLimitExceeded) is not a per-audit failure, so it propagates."""
    try:
        audit = await client.get_audit(audit_id, wait=True)
    except RateLimitExceeded:
        raise
    except Exception:
        return {}
    return {f.get("category", ""): f["compliance_labels"]
            for f in audit.get("findings", []) if f.get("compliance_labels")}


async def _attach_labels(client: "VultureClient", records: list[dict]) -> list[dict]:
    """Give search records the labels of the findings they were made from.

    Memory records carry no labels; their audit's findings do, joined on
    (audit_id, category). One lookup per distinct audit, in relevance order
    and at most _LABEL_LOOKUP_MAX_AUDITS, counting only audits of records that
    can carry a label; a record of a later audit stays unlabelled and so
    matches no framework filter. The lookups stop at the first one the client
    is too busy to serve, so a busy client costs one wait bound rather than
    one per audit. Returns the records and, when some were left unresolved,
    a message saying how many and why (None otherwise)."""
    ordered = list(dict.fromkeys(r["audit_id"] for r in records if _needs_labels(r)))
    wanted = ordered[:_LABEL_LOOKUP_MAX_AUDITS]
    by_audit = await _audit_label_maps(client, wanted)
    return [_with_labels(r, by_audit) for r in records], _left_out_report(records, by_audit, len(wanted))


def _left_out_report(records: list[dict], by_audit: dict, wanted: int) -> str | None:
    """How many records needing a label were left unresolved, and why."""
    left = _unresolved_audit_ids(records, by_audit)
    if not left:
        return None
    why = ("the server was busy with other requests" if len(by_audit) < wanted
           else f"labels are looked up for the {_LABEL_LOOKUP_MAX_AUDITS} most relevant audits only")
    return (f"{len(left)} match(es) from {len(set(left))} audit(s) could not be checked against "
            f"the framework filter and were left out: {why}.")


def _unresolved_audit_ids(records: list[dict], by_audit: dict) -> list[str]:
    """The audit id of every record that needed a label its audit was never asked for."""
    return [r["audit_id"] for r in records if _needs_labels(r) and r["audit_id"] not in by_audit]


async def _warn(ctx: Context | None, message: str) -> None:
    """Report to the operator (stderr) and, within a request, to the client."""
    sys.stderr.write(f"vulture-mcp: warning: {message}\n")
    if ctx is None:
        return
    try:
        await ctx.warning(message)
    except ValueError:  # no request to report to (a direct, request-less call)
        pass


async def _audit_label_maps(client: "VultureClient", audit_ids: list[str]) -> dict[str, dict[str, list[dict]]]:
    """Label maps of audit_ids, fetched in order until the client is too busy."""
    by_audit: dict[str, dict[str, list[dict]]] = {}
    for aid in audit_ids:
        try:
            by_audit[aid] = await _audit_label_map(client, aid)
        except RateLimitExceeded:
            break
    return by_audit


# The backend's label predicate (isLabelCandidate): the mapping labels only a
# CWE-categorised finding of a scan agent, never an OWASP agent row.
_CWE_CATEGORY = re.compile(r"^CWE-\d+$")


def _can_carry_labels(record: dict) -> bool:
    return record.get("agent_type") != "owasp" and bool(_CWE_CATEGORY.match(record.get("category") or ""))


def _needs_labels(record: dict) -> bool:
    """A record needs a lookup when its audit could have labelled it and it
    does not carry labels already. Any other record (a chaos pattern, an OWASP
    agent row, a record without an audit) can never gain a label from one."""
    if "compliance_labels" in record or not _can_carry_labels(record):
        return False
    return bool(record.get("audit_id"))


def _with_labels(record: dict, by_audit: dict[str, dict[str, list[dict]]]) -> dict:
    if not _needs_labels(record):
        return record
    labels = by_audit.get(record["audit_id"], {}).get(record.get("category", ""))
    return dict(record, compliance_labels=labels) if labels else record


def _redact_comparison(comparison: dict) -> dict:
    """Redact sensitive fields in comparison finding lists."""
    out = dict(comparison)
    for key in ("new_findings", "fixed_findings", "changed_findings"):
        if key in out and isinstance(out[key], list):
            out[key] = [_redact_record(f) for f in out[key]]
    return out


# Lineage resolution mirrors the backend writer (`resolveExisting`) and the UI
# findings table (frontend/src/lib/lineage.ts indexLineage/resolveLineage):
# agent-scoped, fingerprint_v2 first, then the v1 fingerprint; v1 alone only
# when the caller knows no agent. v1 alone is not enough — a row recognised
# through v2 keeps its ORIGINAL v1, and several findings can share one v1 while
# each belongs to a different row. First row wins per key (the endpoint returns
# rows newest-updated first).
def _agent_key(agent: str | None) -> str:
    return (agent or "").strip().lower()


def _index_lineage(rows: list) -> dict:
    """Index lineage rows by (agent, v2), (agent, v1) and bare v1."""
    index: dict = {"v2": {}, "v1": {}, "v1_any": {}, "v1_agentless": {}}
    for row in rows:
        agent = _agent_key(row.get("agent_type"))
        fp, fp2 = row.get("fingerprint"), row.get("fingerprint_v2")
        if fp2:
            index["v2"].setdefault((agent, fp2), row)
        if fp:
            index["v1"].setdefault((agent, fp), row)
            index["v1_any"].setdefault(fp, row)
            if not agent:
                index["v1_agentless"].setdefault(fp, row)
    return index


def _resolve_lineage(index: dict, item: dict) -> dict | None:
    """The lineage row a finding (or anything carrying its fingerprints) belongs to."""
    fp, fp2 = item.get("fingerprint"), item.get("fingerprint_v2")
    agent = _agent_key(item.get("agent_type") or item.get("agent_id"))
    if not agent:
        return index["v1_any"].get(fp) if fp else None
    row = index["v2"].get((agent, fp2)) if fp2 else None
    if row is None and fp:
        # A row carrying no agent is resolved as the UI resolves a caller that
        # knows no agent: by v1 alone. The backend always writes agent_type, so
        # this only reaches rows from a client that omits it.
        row = index["v1"].get((agent, fp)) or index["v1_agentless"].get(fp)
    return row


async def _build_lineage_map(client: VultureClient, audit_id: str) -> dict:
    """Build the lineage index for an audit. Returns an empty index on failure."""
    try:
        return _index_lineage(await client.get_audit_lineage(audit_id))
    except Exception:
        return _index_lineage([])


def _compute_ref(lineage: dict) -> str:
    """Compute a VLT-NNNN ref string from a lineage record."""
    ref = lineage.get("ref", "")
    if ref:
        return ref
    rn = lineage.get("ref_number", 0)
    return f"VLT-{rn:04d}" if rn and rn > 0 else ""


def _enrich_finding(finding: dict, lineage_map: dict) -> dict:
    """Add lineage_id, lineage_status, and ref to a finding."""
    result = _redact_record(finding)
    lineage = _resolve_lineage(lineage_map, finding)
    if lineage:
        result["lineage_id"] = lineage.get("id", "")
        result["lineage_status"] = lineage.get("current_status", "open")
        result["ref"] = _compute_ref(lineage)
    return result


async def _resolve_lineage_id(
    ref: str | None, fingerprint: str | None, lineage_id: str | None, audit_id: str | None,
) -> str:
    """Resolve a finding reference to a lineage ID."""
    if lineage_id:
        return lineage_id

    client = await _get_client()

    if ref or fingerprint:
        audit_id = audit_id or await _resolve_audit_id(client)
        lineages = await client.get_audit_lineage(audit_id)
        return _match_lineage(lineages, ref, fingerprint, audit_id)

    raise ValueError("Provide one of: ref, fingerprint, or lineage_id")


async def _resolve_audit_id(client: VultureClient) -> str:
    """Get audit_id from most recent audit when none provided."""
    audits = await client.list_audits(limit=1)
    if not audits:
        raise ValueError("No audits found — provide audit_id explicitly")
    return audits[0].get("id", "")


def _match_lineage(lineages: list, ref: str | None, fingerprint: str | None, audit_id: str) -> str:
    """Find matching lineage ID by ref or fingerprint."""
    if ref:
        for ln in lineages:
            if _compute_ref(ln) == ref:
                return ln["id"]
        raise ValueError(f"Finding ref '{ref}' not found in audit {audit_id}")
    if fingerprint:
        # The caller names a v1 fingerprint and no agent: v1 alone, first row wins.
        lineage = _resolve_lineage(_index_lineage(lineages), {"fingerprint": fingerprint})
        if lineage:
            return lineage["id"]
        raise ValueError(f"Fingerprint '{fingerprint}' not found in audit {audit_id}")
    raise ValueError("Provide one of: ref, fingerprint, or lineage_id")


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def vulture_list_audits(limit: int = 10, status: str | None = None) -> list[dict]:
    """List recent Vulture audits. Returns summaries (no full findings)."""
    client = await _get_client()
    audits = await client.list_audits(limit=limit, status=status)
    for a in audits:
        a.pop("findings", None)
        a.pop("prove_results", None)
        a.pop("webhook_url", None)
    return audits


@mcp.tool()
async def vulture_get_findings(
    audit_id: str,
    severity: str | None = None,
    category: str | None = None,
    agent_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
    framework: str | None = None,
    edition: str | None = None,
    provenance: str | None = None,
) -> dict:
    """Get findings from a specific audit with filtering and pagination.

    provenance filters by the tier that produced a finding, with the same
    vocabulary as the findings API: an exact value ("skill", "llm",
    "llm_l5_verified", "semgrep") matches a finding's provenance literally;
    "llm_family" keeps every finding whose provenance, trimmed and
    lower-cased, starts with "llm"; "both" keeps findings that a skill-family
    tier and an LLM-family tier both reported (validation.provenance_origins;
    a catalog_rollup origin is a grouping, not a tier). A "both" result also
    carries `origins_recorded`: false (with a `note`) when the audit's findings
    record no origins, so an empty result there means "not recorded", not
    "never corroborated".
    The value is case-sensitive; an unknown value selects nothing. It combines
    with the other filters and never changes a finding's validation.

    For an OWASP Top 10 category use framework="owasp" with category="A07";
    framework="owasp" alone returns every finding carrying an OWASP label.
    A category id is edition-specific (A03 is Injection in 2021 but Software
    Supply Chain Failures in 2025): add edition="2025" to keep that edition's
    labels only. With framework, every returned finding carries
    `compliance_labels`, each label naming its `edition`. A pre-0096 OWASP
    agent row (older audits kept them) carries the one label its own check_id
    or category slug names, marked `legacy`: true, with an empty
    category_name; its edition is the one its slug names when only one
    edition uses that slug, otherwise edition "" (unknown), which matches no
    edition filter. OWASP categories are labels (`compliance_labels`) on the CWE-categorised
    findings of the scan agents: the OWASP agent keeps no findings of its own,
    so agent_type is a literal agent filter and agent_type="owasp" returns
    nothing on current audits. Without framework, category matches a
    finding's own category literally (e.g. "CWE-89")."""
    framework, category, edition = _normalize_framework_filter(framework, category, edition)
    client = await _get_client()
    # Forward the provenance filter so a current backend selects server side;
    # the local predicate below still runs, so an older backend that ignores
    # the parameter yields the same rows.
    audit = await client.get_audit(audit_id, params={"provenance": provenance} if provenance else None)
    findings = _framework_output(
        _filter_findings(audit.get("findings", []), severity, category, agent_type, framework, edition,
                         provenance),
        framework)

    # Enrich with lineage status and ref
    lineage_map = await _build_lineage_map(client, audit_id)

    total = len(findings)
    page = findings[offset : offset + limit]
    enriched = [_enrich_finding(f, lineage_map) for f in page]
    has_more = offset + limit < total
    return {
        "findings": enriched,
        "total": total,
        "has_more": has_more,
        "next_offset": offset + limit if has_more else None,
        **_both_marker(provenance, audit),
    }


@mcp.tool()
async def vulture_get_finding_detail(audit_id: str, fingerprint: str) -> dict:
    """Get detailed info for one finding, including current lineage record if available."""
    client = await _get_client()
    audit = await client.get_audit(audit_id)
    finding = next((f for f in audit.get("findings", []) if f.get("fingerprint") == fingerprint), None)
    if not finding:
        raise ValueError(f"Finding with fingerprint {fingerprint} not found in audit {audit_id}")
    result = _redact_record(finding)
    try:
        lineages = await client.get_audit_lineage(audit_id)
        lineage = _resolve_lineage(_index_lineage(lineages), finding)
        if lineage:
            result["lineage"] = _redact_record(lineage)
    except Exception as exc:
        result["lineage_error"] = f"Failed to fetch lineage: {type(exc).__name__}"
    return result


# 0074 verification item 1b. What an MCP client may learn about a masked value:
# where it sits, what kind it is, the length of a fixed-format token, and
# whether the scanned file still reproduces the masked rows. Never the value:
# this output enters the calling model's context.
_SPAN_FIELDS = ("line", "ordinal", "column", "kind", "length")
_MASKED_FIELDS = ("source_available", "matches_scan", "file", "rows_checked", "reason")


def _ui_url(base: str, ui_path: str) -> str:
    """The finding in the UI: VULTURE_FRONTEND_URL when set (the CLI's rule),
    else the server this client talks to (an install or remote server serves
    its own UI)."""
    origin = os.environ.get("VULTURE_FRONTEND_URL", "").strip() or base
    return origin.rstrip("/") + ui_path


@mcp.tool()
async def vulture_verify_masked_values(audit_id: str, fingerprint: str) -> dict:
    """Verify the masked values (secrets) in one finding's code snippet WITHOUT
    receiving them. Returns, per masked value: line, column, kind (jwt,
    url_userinfo, private_key, aws_key_id, ...) and, for fixed-format tokens,
    the length; whether the scanned file still reproduces the masked rows
    (matches_scan); and ui_url, where a human can switch the value on. With
    local file access, read file:line:column yourself. Values are never
    returned by this tool."""
    client = await _get_client()
    audit = await client.get_audit(audit_id)
    finding = next((f for f in audit.get("findings", []) if f.get("fingerprint") == fingerprint), None)
    if not finding or not finding.get("id"):
        raise ValueError(f"Finding with fingerprint {fingerprint} not found in audit {audit_id}")
    masked = await client.get_masked_values(audit_id, finding["id"])
    result = {k: masked[k] for k in _MASKED_FIELDS if k in masked}
    result["spans"] = [{k: span[k] for k in _SPAN_FIELDS if k in span} for span in masked.get("spans") or []]
    result["ui_url"] = _ui_url(client.base_url, masked.get("ui_path") or f"/audit/{audit_id}")
    return result


@mcp.tool()
async def vulture_get_comparison(audit_id: str) -> dict:
    """Compare an audit with the previous one. Shows new, fixed, and changed findings."""
    client = await _get_client()
    comparison = await client.get_comparison(audit_id)
    return _redact_comparison(comparison)


@mcp.tool()
async def vulture_search_findings(
    query: str,
    limit: int = 20,
    framework: str | None = None,
    category: str | None = None,
    edition: str | None = None,
    ctx: Context | None = None,
) -> list[dict]:
    """Semantic search across all audit findings using pgvector embeddings.

    To keep only matches in an OWASP Top 10 category use framework="owasp"
    with category="A07" (framework="owasp" alone keeps every OWASP-labelled
    match); matched records gain `compliance_labels`. A category id is
    edition-specific (A03 is Injection in 2021 but Software Supply Chain
    Failures in 2025) and a search spans audits of either edition, so add
    edition="2025" to keep that edition's labels only; without it results can
    mix editions, each label naming its `edition`. A pre-0096 OWASP record
    (older audits kept OWASP agent rows) carries the one label its own
    category slug or check_id names, marked `legacy`: true, with an empty
    category_name; its edition is the one its slug names when only one
    edition uses that slug, otherwise edition "" (unknown), which matches no
    edition filter. The filter applies to the top `limit` semantic matches.
    Labels are looked up in the audits the matches came from, and only a
    CWE-categorised match of a scan agent can carry one, so only those are
    looked up: for the 10 most relevant such audits, and not once the server
    is busy with other requests. Such a match left unchecked is left out,
    and the tool then sends a warning log message saying how many were left
    out and why. Without framework, category matches a record's own category
    literally (e.g. "CWE-89")."""
    framework, category, edition = _normalize_framework_filter(framework, category, edition)
    client = await _get_client()
    results = await client.search_memories(query, limit=limit)
    if framework:
        results, left_out = await _attach_labels(client, results)
        if left_out:
            await _warn(ctx, left_out)
    results = _framework_output(_filter_findings(results, None, category, None, framework, edition), framework)
    return [_redact_record(r) for r in results]


@mcp.tool()
async def vulture_list_lineage(audit_id: str, status: str | None = None) -> list[dict]:
    """List finding lineage for an audit, optionally filtered by status."""
    client = await _get_client()
    lineages = await client.get_audit_lineage(audit_id)
    if status:
        lineages = [ln for ln in lineages if ln.get("current_status") == status]
    return [_redact_record(ln) for ln in lineages]


@mcp.tool()
async def vulture_update_status(
    status: str,
    ref: str | None = None,
    fingerprint: str | None = None,
    lineage_id: str | None = None,
    audit_id: str | None = None,
    notes: str = "",
) -> dict:
    """Update finding triage status. Accepts ref (VLT-0042), fingerprint, or lineage_id.
    Requires VULTURE_MCP_ALLOW_WRITE=true."""
    if not _allow_write():
        raise PermissionError("write access disabled — set VULTURE_MCP_ALLOW_WRITE=true to enable finding triage")
    if status not in _VALID_STATUSES:
        raise ValueError(f"Invalid status '{status}'. Valid: {', '.join(sorted(_VALID_STATUSES))}")
    resolved_id = await _resolve_lineage_id(ref, fingerprint, lineage_id, audit_id)
    client = await _get_client()
    return await client.update_lineage(resolved_id, status, notes)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    os.environ.setdefault("HTTPX_LOG_LEVEL", "warn")
    transport = os.environ.get("VULTURE_MCP_TRANSPORT", "stdio")
    if transport == "streamable-http":
        url = os.environ.get("VULTURE_URL", "")
        if url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            raise SystemExit("ERROR: VULTURE_URL must use https:// for streamable-http transport")
        port = int(os.environ.get("VULTURE_MCP_PORT", "8100"))
        mcp.run(transport="streamable-http", port=port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
