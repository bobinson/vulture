"""InfraConfigPlugin — discover endpoints from infrastructure configuration files.

Parses Docker Compose, Kubernetes manifests, Nginx/Apache/HAProxy configs,
Terraform files, and .env files to extract service URLs and ports.
"""

import logging
import re
from pathlib import Path

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import extract_urls_from_text, safe_yaml_load

logger = logging.getLogger(__name__)

_CONFIG_PATTERNS: list[tuple[str, str]] = [
    ("docker-compose.yml", "docker_compose"),
    ("docker-compose.yaml", "docker_compose"),
    ("nginx.conf", "nginx"),
    ("haproxy.cfg", "haproxy"),
]

_MAX_CONFIG_FILES = 100


@register_plugin
class InfraConfigPlugin(DiscoveryPlugin):
    """Discover endpoints from Docker Compose, K8s, Nginx, Apache, HAProxy, Terraform, .env."""

    name = "infra_config"
    priority = 22

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return bool(ctx.source_path)

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        root = Path(ctx.source_path)
        if not root.is_dir():
            return result

        scanned = 0
        for fpath in root.rglob("*"):
            if scanned >= _MAX_CONFIG_FILES or not fpath.is_file():
                continue
            parser = _match_parser(fpath)
            if not parser:
                continue
            try:
                content = fpath.read_text(errors="replace")
            except Exception:
                continue
            parser(content, result)
            scanned += 1

        if result.endpoints or result.urls:
            logger.info(
                "InfraConfig: found %d endpoints, %d URLs from config files",
                len(result.endpoints), len(result.urls),
            )
        return result


def _match_parser(fpath: Path):
    """Return the appropriate parser function for a config file, or None."""
    name = fpath.name.lower()
    if name in ("docker-compose.yml", "docker-compose.yaml"):
        return _parse_docker_compose
    if name == "nginx.conf":
        return _parse_nginx_config
    if name == "haproxy.cfg":
        return _parse_haproxy_config
    if name.startswith(".env"):
        return _parse_env_file
    if name.endswith(".tf"):
        return _parse_terraform
    if name.endswith(".conf"):
        return _parse_conf_file
    if name.endswith((".yaml", ".yml")):
        return _parse_yaml_file
    return None


def _parse_conf_file(content: str, result: DiscoveryResult) -> None:
    """Route .conf files to nginx or apache parsers based on content."""
    if "server {" in content:
        _parse_nginx_config(content, result)
    elif "ProxyPass" in content:
        _parse_apache_config(content, result)


def _parse_yaml_file(content: str, result: DiscoveryResult) -> None:
    """Route YAML files to K8s parser if they contain K8s markers."""
    if "kind:" in content and ("Service" in content or "Ingress" in content):
        _parse_kubernetes_manifest(content, result)


def _parse_docker_compose(content: str, result: DiscoveryResult) -> None:
    """Extract service ports and environment URLs from docker-compose."""
    data = safe_yaml_load(content)
    if not isinstance(data, dict):
        return
    services = data.get("services", {})
    if not isinstance(services, dict):
        return
    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        _extract_dc_ports(svc, result)
        _extract_dc_env_urls(svc, result)
        result.technologies.append(f"docker:{svc_name}")


def _extract_dc_ports(svc: dict, result: DiscoveryResult) -> None:
    """Extract port mappings from a docker-compose service."""
    for port_def in svc.get("ports", []):
        port_str = str(port_def)
        if ":" not in port_str:
            continue
        parts = port_str.split(":")
        host_port = parts[-2].split("/")[0]
        try:
            result.metadata.setdefault("infra_ports", []).append(int(host_port))
        except ValueError:
            pass


def _extract_dc_env_urls(svc: dict, result: DiscoveryResult) -> None:
    """Extract URLs from docker-compose service environment."""
    env = svc.get("environment", {})
    items = env.values() if isinstance(env, dict) else env if isinstance(env, list) else []
    for val in items:
        for url in extract_urls_from_text(str(val)):
            result.urls.append(url)


_K8S_PORT_RE = re.compile(r"port:\s*(\d+)")


def _parse_kubernetes_manifest(content: str, result: DiscoveryResult) -> None:
    """Extract service ports and ingress paths from K8s manifests."""
    data = safe_yaml_load(content)
    if not isinstance(data, dict):
        return

    kind = data.get("kind", "")
    handler = _K8S_HANDLERS.get(kind)
    if handler:
        handler(data, result)
        result.technologies.append("Kubernetes")


def _parse_k8s_service(data: dict, result: DiscoveryResult) -> None:
    """Extract ports from a K8s Service manifest."""
    spec = data.get("spec", {})
    for port_def in spec.get("ports", []):
        if not isinstance(port_def, dict):
            continue
        port = port_def.get("port") or port_def.get("targetPort")
        if port:
            result.metadata.setdefault("infra_ports", []).append(int(port))


def _parse_k8s_ingress(data: dict, result: DiscoveryResult) -> None:
    """Extract paths from a K8s Ingress manifest."""
    spec = data.get("spec", {})
    for rule in spec.get("rules", []):
        if not isinstance(rule, dict):
            continue
        for path_def in rule.get("http", {}).get("paths", []):
            if isinstance(path_def, dict):
                path = path_def.get("path", "")
                if path:
                    result.endpoints.append(path)


_K8S_HANDLERS = {"Service": _parse_k8s_service, "Ingress": _parse_k8s_ingress}


_NGINX_PROXY_RE = re.compile(r"proxy_pass\s+(https?://[^\s;]+)")
_NGINX_LOCATION_RE = re.compile(r"location\s+([^\s{]+)")


def _parse_nginx_config(content: str, result: DiscoveryResult) -> None:
    """Extract proxy_pass targets and location blocks from nginx config."""
    for m in _NGINX_PROXY_RE.finditer(content):
        result.urls.append(m.group(1))
    for m in _NGINX_LOCATION_RE.finditer(content):
        loc = m.group(1)
        if loc.startswith("/"):
            result.endpoints.append(loc)
    result.technologies.append("Nginx")


_APACHE_PROXY_RE = re.compile(r"ProxyPass\s+\S+\s+(https?://[^\s]+)")


def _parse_apache_config(content: str, result: DiscoveryResult) -> None:
    """Extract ProxyPass targets from Apache config."""
    for m in _APACHE_PROXY_RE.finditer(content):
        result.urls.append(m.group(1))
    result.technologies.append("Apache")


_HAPROXY_SERVER_RE = re.compile(r"server\s+\S+\s+([\w.-]+:\d+)")


def _parse_haproxy_config(content: str, result: DiscoveryResult) -> None:
    """Extract server lines from HAProxy config."""
    for m in _HAPROXY_SERVER_RE.finditer(content):
        result.urls.append(f"http://{m.group(1)}")
    result.technologies.append("HAProxy")


_TF_API_RE = re.compile(r"""route_key\s*=\s*["'](\S+\s+/[^"']+)["']""")


def _parse_terraform(content: str, result: DiscoveryResult) -> None:
    """Extract API Gateway routes from Terraform HCL."""
    for m in _TF_API_RE.finditer(content):
        parts = m.group(1).split(maxsplit=1)
        if len(parts) == 2:
            result.endpoints.append(parts[1])
    result.technologies.append("Terraform")


def _parse_env_file(content: str, result: DiscoveryResult) -> None:
    """Extract URLs from .env files."""
    for url in extract_urls_from_text(content):
        result.urls.append(url)
