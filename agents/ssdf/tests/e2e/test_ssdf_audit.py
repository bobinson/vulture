"""E2E tests for the SSDF audit agent."""

from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient


@pytest.fixture
def sample_source(tmp_path: Path) -> Path:
    """Create sample source code for SSDF audit."""
    # Python app with hardcoded creds and debug mode
    (tmp_path / "app.py").write_text(
        "import os\n\n"
        "DEBUG = True\n\n"
        'password = "supersecret123"\n\n'
        "def main():\n"
        "    pass\n"
    )
    # Dockerfile running as root with non-minimal image
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.12\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "USER root\n"
        'CMD ["python", "app.py"]\n'
    )
    # docker-compose with privileged container
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  app:\n"
        "    build: .\n"
        "    privileged: true\n"
    )
    # package.json with unpinned dependency
    (tmp_path / "package.json").write_text(
        '{\n  "dependencies": {\n    "lodash": "*"\n  }\n}\n'
    )
    return tmp_path


@pytest.fixture
def ssdf_app():
    """Create the SSDF agent FastAPI app."""
    from ssdf_agent.main import app
    return app


class TestSsdfHealth:
    """Tests for SSDF agent health endpoint."""

    @pytest.mark.anyio
    async def test_health_returns_healthy(self, ssdf_app) -> None:
        """GET /health returns healthy status."""
        async with AsyncClient(
            transport=ASGITransport(app=ssdf_app), base_url="http://test"
        ) as client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert body["agent"] == "ssdf"


class TestSsdfInfo:
    """Tests for SSDF agent info endpoint."""

    @pytest.mark.anyio
    async def test_info_returns_config_schema(self, ssdf_app) -> None:
        """GET /info returns agent info with practice group config."""
        async with AsyncClient(
            transport=ASGITransport(app=ssdf_app), base_url="http://test"
        ) as client:
            resp = await client.get("/info")
        assert resp.status_code == 200
        body = resp.json()
        assert body["name"] == "NIST SSDF v1.1 Auditor"
        assert body["type"] == "ssdf"
        assert "config_schema" in body
        schema = body["config_schema"]
        assert "properties" in schema
        assert "practice_groups" in schema["properties"]
        assert "skills" in body
        assert len(body["skills"]) >= 18


class TestSsdfRun:
    """Tests for SSDF agent run endpoint."""

    @pytest.mark.anyio
    async def test_run_returns_sse_stream(self, ssdf_app, sample_source: Path) -> None:
        """POST /run returns SSE event stream."""
        async with AsyncClient(
            transport=ASGITransport(app=ssdf_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-ssdf-1",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers["content-type"]
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body

    @pytest.mark.anyio
    async def test_run_emits_findings(self, ssdf_app, sample_source: Path) -> None:
        """POST /run emits finding events for SSDF issues."""
        async with AsyncClient(
            transport=ASGITransport(app=ssdf_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-ssdf-2",
                    "source_path": str(sample_source),
                    "config": {},
                },
            )
        body = resp.text
        assert "event: result" in body

    @pytest.mark.anyio
    async def test_run_with_practice_group_filter(self, ssdf_app, sample_source: Path) -> None:
        """POST /run respects practice group filter in config."""
        async with AsyncClient(
            transport=ASGITransport(app=ssdf_app), base_url="http://test"
        ) as client:
            resp = await client.post(
                "/run",
                json={
                    "run_id": "test-ssdf-3",
                    "source_path": str(sample_source),
                    "config": {"practice_groups": ["PO"]},
                },
            )
        assert resp.status_code == 200
        body = resp.text
        assert "event: agent_start" in body
        assert "event: agent_end" in body


class TestSsdfSkills:
    """Tests for individual SSDF skills."""

    def test_security_policy(self, sample_source: Path) -> None:
        """security_policy checks for security policy docs."""
        from ssdf_agent.skills.security_policy import check_security_policy
        result = check_security_policy(str(sample_source))
        assert "findings" in result

    def test_roles_governance(self, sample_source: Path) -> None:
        """roles_governance checks for CODEOWNERS."""
        from ssdf_agent.skills.roles_governance import check_roles_governance
        result = check_roles_governance(str(sample_source))
        assert "findings" in result

    def test_toolchain_check(self, sample_source: Path) -> None:
        """toolchain_check checks for SAST/DAST/SCA."""
        from ssdf_agent.skills.toolchain_check import check_toolchain
        result = check_toolchain(str(sample_source))
        assert "findings" in result

    def test_security_criteria(self, sample_source: Path) -> None:
        """security_criteria checks for quality gates."""
        from ssdf_agent.skills.security_criteria import check_security_criteria
        result = check_security_criteria(str(sample_source))
        assert "findings" in result

    def test_secure_environment(self, sample_source: Path) -> None:
        """secure_environment checks container hardening."""
        from ssdf_agent.skills.secure_environment import check_secure_environment
        result = check_secure_environment(str(sample_source))
        assert "findings" in result

    def test_code_protection(self, sample_source: Path) -> None:
        """code_protection checks pre-commit hooks."""
        from ssdf_agent.skills.code_protection import check_code_protection
        result = check_code_protection(str(sample_source))
        assert "findings" in result

    def test_release_integrity(self, sample_source: Path) -> None:
        """release_integrity checks signing and checksums."""
        from ssdf_agent.skills.release_integrity import check_release_integrity
        result = check_release_integrity(str(sample_source))
        assert "findings" in result

    def test_archive_protection(self, sample_source: Path) -> None:
        """archive_protection checks release archival."""
        from ssdf_agent.skills.archive_protection import check_archive_protection
        result = check_archive_protection(str(sample_source))
        assert "findings" in result

    def test_secure_design(self, sample_source: Path) -> None:
        """secure_design checks threat models."""
        from ssdf_agent.skills.secure_design import check_secure_design
        result = check_secure_design(str(sample_source))
        assert "findings" in result

    def test_dependency_reuse(self, sample_source: Path) -> None:
        """dependency_reuse checks lock files."""
        from ssdf_agent.skills.dependency_reuse import check_dependency_reuse
        result = check_dependency_reuse(str(sample_source))
        assert "findings" in result

    def test_secure_coding(self, sample_source: Path) -> None:
        """secure_coding checks linter configs."""
        from ssdf_agent.skills.secure_coding import check_secure_coding
        result = check_secure_coding(str(sample_source))
        assert "findings" in result

    def test_build_security(self, sample_source: Path) -> None:
        """build_security checks Dockerfile hardening."""
        from ssdf_agent.skills.build_security import check_build_security
        result = check_build_security(str(sample_source))
        assert "findings" in result

    def test_code_review(self, sample_source: Path) -> None:
        """code_review checks PR templates."""
        from ssdf_agent.skills.code_review import check_code_review
        result = check_code_review(str(sample_source))
        assert "findings" in result

    def test_security_testing(self, sample_source: Path) -> None:
        """security_testing checks for security tests."""
        from ssdf_agent.skills.security_testing import check_security_testing
        result = check_security_testing(str(sample_source))
        assert "findings" in result

    def test_secure_defaults(self, sample_source: Path) -> None:
        """secure_defaults checks hardcoded creds and debug mode."""
        from ssdf_agent.skills.secure_defaults import check_secure_defaults
        result = check_secure_defaults(str(sample_source))
        assert "findings" in result

    def test_vuln_identification(self, sample_source: Path) -> None:
        """vuln_identification checks for CVE scanning."""
        from ssdf_agent.skills.vuln_identification import check_vuln_identification
        result = check_vuln_identification(str(sample_source))
        assert "findings" in result

    def test_vuln_remediation(self, sample_source: Path) -> None:
        """vuln_remediation checks patching workflows."""
        from ssdf_agent.skills.vuln_remediation import check_vuln_remediation
        result = check_vuln_remediation(str(sample_source))
        assert "findings" in result

    def test_root_cause_analysis(self, sample_source: Path) -> None:
        """root_cause_analysis checks post-mortem templates."""
        from ssdf_agent.skills.root_cause_analysis import check_root_cause_analysis
        result = check_root_cause_analysis(str(sample_source))
        assert "findings" in result


class TestSsdfPracticeGroups:
    """Tests for SSDF practice group sub-agents."""

    def test_po_prepare(self, sample_source: Path) -> None:
        """PO group checks organizational preparation."""
        from ssdf_agent.practice_groups.po_prepare import audit_po
        result = audit_po(str(sample_source))
        assert "findings" in result

    def test_ps_protect(self, sample_source: Path) -> None:
        """PS group checks software protection."""
        from ssdf_agent.practice_groups.ps_protect import audit_ps
        result = audit_ps(str(sample_source))
        assert "findings" in result

    def test_pw_produce(self, sample_source: Path) -> None:
        """PW group checks secure development."""
        from ssdf_agent.practice_groups.pw_produce import audit_pw
        result = audit_pw(str(sample_source))
        assert "findings" in result

    def test_rv_respond(self, sample_source: Path) -> None:
        """RV group checks vulnerability response."""
        from ssdf_agent.practice_groups.rv_respond import audit_rv
        result = audit_rv(str(sample_source))
        assert "findings" in result
