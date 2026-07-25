"""EnvServiceURLsPlugin — extract semantically meaningful URLs from env files.

Goes beyond raw URL extraction (handled by ``infra_config``) to understand
what each environment variable *means* — e.g. ``OIDC_ISSUER`` implies a
``.well-known/openid-configuration`` endpoint, ``DATABASE_URL`` implies
PostgreSQL technology, ``NEXTAUTH_URL`` implies NextAuth routes.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import extract_urls_from_text, safe_yaml_load

logger = logging.getLogger(__name__)

_ENV_GLOBS = [".env", ".env.*", "env.yaml", "env.yml"]
_MAX_FILES = 20

_KV_RE = re.compile(r"^([A-Z_][A-Z0-9_]*)=(.+)$", re.MULTILINE)

_SEMANTIC_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"NEXTAUTH_URL$"), "nextauth"),
    (re.compile(r"OIDC_ISSUER$"), "oidc_issuer"),
    (re.compile(r"DATABASE_URL$"), "database"),
    (re.compile(r"REDIS_URL$"), "redis"),
    (re.compile(r"VAULT_ADDR$"), "vault"),
    (re.compile(r"BLOCKCHAIN_ADDR$"), "blockchain"),
    (re.compile(r".*(?:WEBHOOK|CALLBACK)_URL$"), "webhook_url"),
    (re.compile(r".*(?:_URL|_ENDPOINT|_BASE_URL|_API_URL)$"), "service_url"),
]

_TECH_MAP: dict[str, str] = {
    "database": "PostgreSQL",
    "redis": "Redis",
    "vault": "HashiCorp Vault",
    "blockchain": "Blockchain",
}

_OIDC_WELLKNOWN = "/.well-known/openid-configuration"


@register_plugin
class EnvServiceURLsPlugin(DiscoveryPlugin):
    """Extract semantic meaning from environment variable URLs."""

    name = "env_service_urls"
    priority = 26

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return bool(ctx.source_path)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        if not root.is_dir():
            return result

        env_vars = _collect_env_vars(root)
        if not env_vars:
            return result

        existing_urls = set(ctx.site.urls)
        tech_set: set[str] = set()
        env_map: dict[str, str] = {}

        for var_name, value in env_vars.items():
            _process_var(var_name, value, result, existing_urls, tech_set, env_map)

        result.technologies = sorted(tech_set)
        if env_map:
            result.metadata["env_service_urls"] = env_map

        if result.endpoints or result.urls:
            logger.info(
                "EnvServiceURLs: found %d endpoints, %d URLs",
                len(result.endpoints), len(result.urls),
            )
        return result


def _collect_env_vars(root: Path) -> dict[str, str]:
    """Collect environment variables from .env* and env.yaml files."""
    env_vars: dict[str, str] = {}
    found = 0

    for fpath in root.iterdir():
        if found >= _MAX_FILES:
            break
        if not fpath.is_file():
            continue
        name = fpath.name
        if _is_env_file(name):
            found += 1
            _parse_into(fpath, env_vars)
    return env_vars


def _is_env_file(name: str) -> bool:
    """Check if filename matches env file patterns."""
    if name.startswith(".env"):
        return True
    if name in ("env.yaml", "env.yml"):
        return True
    return False


def _parse_into(fpath: Path, env_vars: dict[str, str]) -> None:
    """Parse a single env file into the vars dict."""
    try:
        content = fpath.read_text(errors="replace")
    except Exception:
        return

    if fpath.suffix in (".yaml", ".yml"):
        _parse_yaml_env(content, env_vars)
    else:
        _parse_dotenv(content, env_vars)


def _parse_dotenv(content: str, env_vars: dict[str, str]) -> None:
    """Parse KEY=VALUE lines from a .env file."""
    for m in _KV_RE.finditer(content):
        key = m.group(1)
        val = m.group(2).strip().strip("'\"")
        if val:
            env_vars[key] = val


def _parse_yaml_env(content: str, env_vars: dict[str, str]) -> None:
    """Parse environment variables from a YAML file."""
    data = safe_yaml_load(content)
    if isinstance(data, dict):
        _flatten_yaml(data, "", env_vars)


def _flatten_yaml(data: dict, prefix: str, env_vars: dict[str, str]) -> None:
    """Flatten nested YAML into KEY=VALUE pairs."""
    for key, val in data.items():
        full_key = f"{prefix}{key}".upper() if not prefix else f"{prefix}_{key}".upper()
        if isinstance(val, dict):
            _flatten_yaml(val, full_key, env_vars)
        elif isinstance(val, str) and val:
            env_vars[full_key] = val


def _process_var(
    var_name: str, value: str,
    result: DiscoveryResult, existing_urls: set[str],
    tech_set: set[str], env_map: dict[str, str],
) -> None:
    """Apply semantic rules to a single environment variable."""
    for pattern, category in _SEMANTIC_RULES:
        if not pattern.search(var_name):
            continue
        env_map[var_name] = value
        _apply_category(category, value, result, existing_urls, tech_set)
        return


_TECH_CATEGORIES: dict[str, str] = {
    "oidc_issuer": "OIDC",
    "nextauth": "NextAuth",
}

_URL_CATEGORIES = {"nextauth", "webhook_url", "service_url"}


def _apply_category(
    category: str, value: str,
    result: DiscoveryResult, existing_urls: set[str], tech_set: set[str],
) -> None:
    """Apply the semantic category to produce endpoints/technologies."""
    tech = _TECH_MAP.get(category)
    if tech:
        tech_set.add(tech)

    extra_tech = _TECH_CATEGORIES.get(category)
    if extra_tech:
        tech_set.add(extra_tech)

    if category == "oidc_issuer":
        result.endpoints.append(value.rstrip("/") + _OIDC_WELLKNOWN)

    if category in _URL_CATEGORIES:
        _add_new_urls(value, result, existing_urls)


def _add_new_urls(
    value: str, result: DiscoveryResult, existing_urls: set[str],
) -> None:
    """Extract and add URLs that aren't already known."""
    for url in extract_urls_from_text(value):
        if url not in existing_urls:
            result.urls.append(url)
