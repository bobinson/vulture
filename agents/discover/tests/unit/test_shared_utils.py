"""Tests for plugin shared utilities (_shared.py)."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
from xml.etree.ElementTree import Element

import httpx
import pytest

from discover_agent.plugins._shared import (
    detect_dependencies,
    extract_ports_from_text,
    extract_urls_from_text,
    has_dependency,
    probe_endpoint,
    probe_http_port,
    probe_port,
    safe_xml_parse,
    safe_yaml_load,
)


# --- Port probing ---


class TestProbePort:
    """Tests for probe_port TCP probing."""

    @pytest.mark.asyncio
    async def test_open_port(self):
        """probe_port returns True when connection succeeds."""
        mock_writer = MagicMock()
        mock_writer.close = MagicMock()
        mock_writer.wait_closed = AsyncMock()

        with patch(
            "discover_agent.plugins._shared.asyncio.wait_for",
            new_callable=AsyncMock,
            return_value=(MagicMock(), mock_writer),
        ):
            result = await probe_port("localhost", 8080)
            assert result is True

    @pytest.mark.asyncio
    async def test_closed_port(self):
        """probe_port returns False when connection fails."""
        with patch("discover_agent.plugins._shared.asyncio.wait_for", side_effect=OSError):
            result = await probe_port("localhost", 9999)
            assert result is False

    @pytest.mark.asyncio
    async def test_timeout(self):
        """probe_port returns False on timeout."""
        with patch("discover_agent.plugins._shared.asyncio.wait_for", side_effect=asyncio.TimeoutError):
            result = await probe_port("localhost", 8080, timeout=0.1)
            assert result is False


class TestProbeHttpPort:
    """Tests for probe_http_port."""

    @pytest.mark.asyncio
    async def test_successful_probe(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        client.get = AsyncMock(return_value=resp)

        result = await probe_http_port(client, "http://localhost:8080", 9090)
        assert result is not None
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_failed_probe(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        client.get = AsyncMock(side_effect=httpx.ConnectError("fail"))

        result = await probe_http_port(client, "http://localhost:8080", 9090)
        assert result is None


class TestProbeEndpoint:
    """Tests for generic probe_endpoint."""

    @pytest.mark.asyncio
    async def test_get_endpoint(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        client.request = AsyncMock(return_value=resp)

        ok, result = await probe_endpoint(client, "http://example.com/api")
        assert ok is True
        assert result is not None

    @pytest.mark.asyncio
    async def test_post_with_body(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        client.request = AsyncMock(return_value=resp)

        ok, result = await probe_endpoint(
            client, "http://example.com/api",
            method="POST", body='{"test": true}',
            headers={"Content-Type": "application/json"},
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_connection_error(self):
        client = AsyncMock(spec=httpx.AsyncClient)
        client.request = AsyncMock(side_effect=httpx.ConnectError("fail"))

        ok, result = await probe_endpoint(client, "http://example.com/api")
        assert ok is False
        assert result is None


# --- Dependency detection ---


class TestDetectDependencies:
    """Tests for detect_dependencies and has_dependency."""

    def test_node_deps(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"express": "^4.0", "@nestjs/core": "^10"}}')
        deps = detect_dependencies(tmp_path)
        assert "node" in deps
        assert "express" in deps["node"]
        assert "@nestjs/core" in deps["node"]

    def test_python_deps(self, tmp_path: Path):
        req = tmp_path / "requirements.txt"
        req.write_text("flask>=2.0\nrequests\npyyaml>=6.0")
        deps = detect_dependencies(tmp_path)
        assert "python" in deps
        assert "flask" in deps["python"]

    def test_go_deps(self, tmp_path: Path):
        gomod = tmp_path / "go.mod"
        gomod.write_text("module example.com/app\nrequire (\n\tgithub.com/gin-gonic/gin v1.9\n)")
        deps = detect_dependencies(tmp_path)
        assert "go" in deps
        assert "github.com/gin-gonic/gin" in deps["go"]

    def test_rust_deps(self, tmp_path: Path):
        cargo = tmp_path / "Cargo.toml"
        cargo.write_text('[dependencies]\nactix-web = "4"\ntokio = "1"')
        deps = detect_dependencies(tmp_path)
        assert "rust" in deps
        assert "actix-web" in deps["rust"]

    def test_ruby_deps(self, tmp_path: Path):
        gemfile = tmp_path / "Gemfile"
        gemfile.write_text('gem "rails"\ngem "puma"')
        deps = detect_dependencies(tmp_path)
        assert "ruby" in deps
        assert "rails" in deps["ruby"]

    def test_java_deps(self, tmp_path: Path):
        pom = tmp_path / "pom.xml"
        pom.write_text("<project><dependencies><dependency><artifactId>spring-boot</artifactId></dependency></dependencies></project>")
        deps = detect_dependencies(tmp_path)
        assert "java" in deps
        assert "spring-boot" in deps["java"]

    def test_php_deps(self, tmp_path: Path):
        composer = tmp_path / "composer.json"
        composer.write_text('{"require": {"laravel/framework": "^10"}}')
        deps = detect_dependencies(tmp_path)
        assert "php" in deps

    def test_dart_deps(self, tmp_path: Path):
        pubspec = tmp_path / "pubspec.yaml"
        pubspec.write_text("dependencies:\n  http: ^1.0\n  dio: ^5.0")
        deps = detect_dependencies(tmp_path)
        assert "dart" in deps
        assert "http" in deps["dart"]

    def test_has_dependency_true(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"web3": "^4.0"}}')
        assert has_dependency(tmp_path, {"web3", "ethers"}) is True

    def test_has_dependency_false(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text('{"dependencies": {"react": "^18.0"}}')
        assert has_dependency(tmp_path, {"web3", "ethers"}) is False

    def test_no_manifest_files(self, tmp_path: Path):
        deps = detect_dependencies(tmp_path)
        assert deps == {}

    def test_malformed_file(self, tmp_path: Path):
        pkg = tmp_path / "package.json"
        pkg.write_text("not json at all {{{")
        deps = detect_dependencies(tmp_path)
        # Should still find regex matches
        assert isinstance(deps, dict)


# --- Config parsing ---


class TestSafeYamlLoad:
    """Tests for safe_yaml_load."""

    def test_valid_yaml(self):
        result = safe_yaml_load("key: value\nlist:\n  - a\n  - b")
        assert isinstance(result, dict)
        assert result["key"] == "value"

    def test_invalid_yaml(self):
        result = safe_yaml_load("{{{{invalid yaml")
        assert result is None

    def test_empty_string(self):
        result = safe_yaml_load("")
        assert result is None


class TestSafeXmlParse:
    """Tests for safe_xml_parse."""

    def test_valid_xml(self):
        result = safe_xml_parse("<root><child>text</child></root>")
        assert result is not None
        assert isinstance(result, Element)
        assert result.tag == "root"

    def test_invalid_xml(self):
        result = safe_xml_parse("not xml at all <<<")
        assert result is None

    def test_empty_string(self):
        result = safe_xml_parse("")
        assert result is None


# --- URL/port extraction ---


class TestExtractUrls:
    """Tests for extract_urls_from_text."""

    def test_extracts_http_urls(self):
        text = 'Backend at http://localhost:8080 and https://api.example.com/v1'
        urls = extract_urls_from_text(text)
        assert "http://localhost:8080" in urls
        assert "https://api.example.com/v1" in urls

    def test_deduplicates(self):
        text = "http://example.com http://example.com"
        urls = extract_urls_from_text(text)
        assert len(urls) == 1

    def test_empty_text(self):
        assert extract_urls_from_text("") == []

    def test_no_urls(self):
        assert extract_urls_from_text("no urls here") == []


class TestExtractPorts:
    """Tests for extract_ports_from_text."""

    def test_extracts_ports(self):
        text = "port :8080 and :3000/api"
        ports = extract_ports_from_text(text)
        assert 8080 in ports
        assert 3000 in ports

    def test_filters_invalid_ports(self):
        text = ":0 :99999"
        ports = extract_ports_from_text(text)
        assert 0 not in ports

    def test_deduplicates(self):
        text = ":8080 :8080"
        ports = extract_ports_from_text(text)
        assert ports.count(8080) == 1

    def test_empty_text(self):
        assert extract_ports_from_text("") == []
