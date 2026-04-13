"""MQTTAMQPPlugin — discover message broker endpoints.

Probes MQTT WebSocket (port 9001), RabbitMQ management API (port 15672),
detects messaging dependencies from source code, and extracts broker URLs.
"""

import logging
import re
from pathlib import Path
from urllib.parse import urlparse

from shared.discovery.plugin_base import DiscoveryContext, DiscoveryPlugin, DiscoveryResult, register_plugin
from discover_agent.plugins._shared import has_dependency, probe_endpoint, probe_port

logger = logging.getLogger(__name__)

_MQTT_DEPS = {"mqtt", "mqtt.js", "paho-mqtt", "mqttasgi", "gmqtt", "rumqttc"}
_AMQP_DEPS = {"amqplib", "pika", "bunny", "amqp", "lapin", "aio-pika"}
_KAFKA_DEPS = {"kafkajs", "confluent-kafka", "sarama", "kafka-python", "rdkafka"}

_BROKER_URL_RE = re.compile(
    r"""(amqps?://[^\s"'`]+|mqtts?://[^\s"'`]+|kafka://[^\s"'`]+)""",
)


@register_plugin
class MQTTAMQPPlugin(DiscoveryPlugin):
    """Discover MQTT, RabbitMQ, and Kafka message broker endpoints."""

    name = "mqtt_amqp"
    priority = 65

    async def accepts(self, ctx: DiscoveryContext) -> bool:
        return True

    async def discover(self, ctx: DiscoveryContext) -> DiscoveryResult:
        result = DiscoveryResult()
        parsed = urlparse(ctx.staging_url)
        host = parsed.hostname or "localhost"

        # 1. Probe MQTT WebSocket (port 9001)
        await _probe_mqtt_ws(host, result)

        # 2. Probe RabbitMQ management API (port 15672)
        await _probe_rabbitmq_mgmt(host, result)

        # 3. Detect messaging deps from source
        if ctx.source_path:
            root = Path(ctx.source_path)
            if has_dependency(root, _MQTT_DEPS):
                result.technologies.append("MQTT")
            if has_dependency(root, _AMQP_DEPS):
                result.technologies.append("AMQP")
            if has_dependency(root, _KAFKA_DEPS):
                result.technologies.append("Kafka")

        # 4. Extract broker URLs from source
        if ctx.source_path:
            _scan_broker_urls(Path(ctx.source_path), result)

        return result


async def _probe_mqtt_ws(host: str, result: DiscoveryResult) -> None:
    """Probe for MQTT over WebSocket on port 9001."""
    if not await probe_port(host, 9001, timeout=3.0):
        return
    try:
        import websockets  # type: ignore[import-untyped]
        # MQTT CONNECT packet (minimal valid packet)
        mqtt_connect = bytes([
            0x10,  # CONNECT packet type
            0x0C,  # Remaining length
            0x00, 0x04,  # Protocol name length
            0x4D, 0x51, 0x54, 0x54,  # "MQTT"
            0x04,  # Protocol level (MQTT 3.1.1)
            0x02,  # Connect flags (clean session)
            0x00, 0x3C,  # Keep alive (60s)
            0x00, 0x00,  # Client ID length (empty)
        ])
        async with websockets.connect(
            f"ws://{host}:9001/mqtt",
            subprotocols=["mqtt"],
            open_timeout=3,
            close_timeout=2,
        ) as ws:
            await ws.send(mqtt_connect)
            result.technologies.append("MQTT/WebSocket")
            result.metadata.setdefault("mqtt_topics", [])
            result.metadata["mqtt_ws_port"] = 9001
            logger.info("MQTT/WebSocket detected on %s:9001", host)
    except Exception:
        pass


async def _probe_rabbitmq_mgmt(host: str, result: DiscoveryResult) -> None:
    """Probe RabbitMQ management API on port 15672."""
    if not await probe_port(host, 15672, timeout=3.0):
        return
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            ok, resp = await probe_endpoint(
                client, f"http://{host}:15672/api/overview",
                headers={"Authorization": "Basic Z3Vlc3Q6Z3Vlc3Q="},  # guest:guest
                timeout=5.0,
            )
            if ok and resp is not None and resp.status_code == 200:
                result.technologies.append("RabbitMQ")
                result.endpoints.append(f"http://{host}:15672/api/overview")
                result.metadata["rabbitmq_mgmt_port"] = 15672
                logger.info("RabbitMQ management API detected on %s:15672", host)
    except Exception:
        pass


def _scan_broker_urls(root: Path, result: DiscoveryResult) -> None:
    """Extract broker URLs from source and config files."""
    scanned = 0
    for fpath in root.rglob("*"):
        if scanned >= 50:
            break
        if not fpath.is_file():
            continue
        if fpath.suffix.lower() not in (
            ".js", ".ts", ".py", ".go", ".java", ".yaml", ".yml",
            ".json", ".env", ".toml", ".conf", ".cfg", ".properties",
        ):
            continue
        try:
            content = fpath.read_text(errors="replace")
        except Exception:
            continue
        scanned += 1

        for m in _BROKER_URL_RE.finditer(content):
            url = m.group(1)
            if url not in result.urls:
                result.urls.append(url)
                result.metadata.setdefault("broker_urls", []).append(url)
