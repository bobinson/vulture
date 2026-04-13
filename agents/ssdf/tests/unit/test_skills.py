"""Unit tests for SSDF skills."""

from pathlib import Path

import pytest


@pytest.fixture
def empty_source(tmp_path: Path) -> Path:
    """Create an empty source directory."""
    return tmp_path


@pytest.fixture
def source_with_security_policy(tmp_path: Path) -> Path:
    """Create source with SECURITY.md."""
    (tmp_path / "SECURITY.md").write_text("# Security Policy\nReport vulnerabilities to security@example.com\n")
    return tmp_path


@pytest.fixture
def source_with_codeowners(tmp_path: Path) -> Path:
    """Create source with CODEOWNERS."""
    (tmp_path / "CODEOWNERS").write_text("* @org/team\n")
    return tmp_path


@pytest.fixture
def source_with_sast(tmp_path: Path) -> Path:
    """Create source with SAST in CI."""
    workflows = tmp_path / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "ci.yml").write_text("jobs:\n  scan:\n    run: semgrep --config auto\n")
    return tmp_path


@pytest.fixture
def source_with_pre_commit(tmp_path: Path) -> Path:
    """Create source with pre-commit hooks."""
    (tmp_path / ".pre-commit-config.yaml").write_text("repos:\n  - repo: https://github.com/pre-commit/pre-commit-hooks\n")
    return tmp_path


@pytest.fixture
def source_with_lock_file(tmp_path: Path) -> Path:
    """Create source with lock file."""
    (tmp_path / "package-lock.json").write_text("{}\n")
    return tmp_path


@pytest.fixture
def source_with_linter(tmp_path: Path) -> Path:
    """Create source with linter config."""
    (tmp_path / ".eslintrc.json").write_text('{"rules": {}}\n')
    return tmp_path


@pytest.fixture
def source_with_hardcoded_creds(tmp_path: Path) -> Path:
    """Create source with hardcoded credentials."""
    (tmp_path / "config.py").write_text('password = "mysecretpassword"\n')
    return tmp_path


@pytest.fixture
def source_with_debug(tmp_path: Path) -> Path:
    """Create source with debug mode enabled."""
    (tmp_path / "settings.py").write_text("DEBUG = True\n")
    return tmp_path


@pytest.fixture
def source_with_dockerfile(tmp_path: Path) -> Path:
    """Create source with Dockerfile."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.12-slim\nWORKDIR /app\nCOPY . .\n")
    return tmp_path


@pytest.fixture
def source_with_root_dockerfile(tmp_path: Path) -> Path:
    """Create source with Dockerfile running as root."""
    (tmp_path / "Dockerfile").write_text("FROM python:3.12\nUSER root\nCOPY . .\n")
    return tmp_path


class TestPO1SecurityPolicy:
    """Tests for PO.1 security policy skill."""

    def test_missing_policy_flagged(self, empty_source: Path) -> None:
        from ssdf_agent.skills.security_policy import check_security_policy
        result = check_security_policy(str(empty_source))
        assert len(result["findings"]) == 1
        assert result["findings"][0]["check_id"] == "ssdf.po1.missing_security_policy"

    def test_present_policy_clean(self, source_with_security_policy: Path) -> None:
        from ssdf_agent.skills.security_policy import check_security_policy
        result = check_security_policy(str(source_with_security_policy))
        assert len(result["findings"]) == 0


class TestPO2RolesGovernance:
    """Tests for PO.2 roles governance skill."""

    def test_missing_codeowners_flagged(self, empty_source: Path) -> None:
        from ssdf_agent.skills.roles_governance import check_roles_governance
        result = check_roles_governance(str(empty_source))
        assert len(result["findings"]) == 1
        assert result["findings"][0]["check_id"] == "ssdf.po2.missing_codeowners"

    def test_present_codeowners_clean(self, source_with_codeowners: Path) -> None:
        from ssdf_agent.skills.roles_governance import check_roles_governance
        result = check_roles_governance(str(source_with_codeowners))
        assert len(result["findings"]) == 0


class TestPO3Toolchain:
    """Tests for PO.3 toolchain skill."""

    def test_no_ci_flags_all(self, empty_source: Path) -> None:
        from ssdf_agent.skills.toolchain_check import check_toolchain
        result = check_toolchain(str(empty_source))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.po3.no_sast_tool" in check_ids
        assert "ssdf.po3.no_dast_tool" in check_ids
        assert "ssdf.po3.no_sca_tool" in check_ids

    def test_sast_present_reduces_findings(self, source_with_sast: Path) -> None:
        from ssdf_agent.skills.toolchain_check import check_toolchain
        result = check_toolchain(str(source_with_sast))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.po3.no_sast_tool" not in check_ids


class TestPS1CodeProtection:
    """Tests for PS.1 code protection skill."""

    def test_no_hooks_flagged(self, empty_source: Path) -> None:
        from ssdf_agent.skills.code_protection import check_code_protection
        result = check_code_protection(str(empty_source))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.ps1.no_pre_commit_hooks" in check_ids

    def test_pre_commit_present_clean(self, source_with_pre_commit: Path) -> None:
        from ssdf_agent.skills.code_protection import check_code_protection
        result = check_code_protection(str(source_with_pre_commit))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.ps1.no_pre_commit_hooks" not in check_ids


class TestPW4DependencyReuse:
    """Tests for PW.4 dependency reuse skill."""

    def test_no_lock_file_flagged(self, empty_source: Path) -> None:
        from ssdf_agent.skills.dependency_reuse import check_dependency_reuse
        result = check_dependency_reuse(str(empty_source))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.pw4.no_lock_file" in check_ids

    def test_lock_file_present_clean(self, source_with_lock_file: Path) -> None:
        from ssdf_agent.skills.dependency_reuse import check_dependency_reuse
        result = check_dependency_reuse(str(source_with_lock_file))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.pw4.no_lock_file" not in check_ids


class TestPW5SecureCoding:
    """Tests for PW.5 secure coding skill."""

    def test_no_linter_flagged(self, empty_source: Path) -> None:
        from ssdf_agent.skills.secure_coding import check_secure_coding
        result = check_secure_coding(str(empty_source))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.pw5.no_linter_config" in check_ids

    def test_linter_present_clean(self, source_with_linter: Path) -> None:
        from ssdf_agent.skills.secure_coding import check_secure_coding
        result = check_secure_coding(str(source_with_linter))
        assert len(result["findings"]) == 0


class TestPW6BuildSecurity:
    """Tests for PW.6 build security skill."""

    def test_non_minimal_image_flagged(self, source_with_root_dockerfile: Path) -> None:
        from ssdf_agent.skills.build_security import check_build_security
        result = check_build_security(str(source_with_root_dockerfile))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.pw6.no_minimal_base_image" in check_ids

    def test_slim_image_clean(self, source_with_dockerfile: Path) -> None:
        from ssdf_agent.skills.build_security import check_build_security
        result = check_build_security(str(source_with_dockerfile))
        assert len(result["findings"]) == 0


class TestPW9SecureDefaults:
    """Tests for PW.9 secure defaults skill."""

    def test_hardcoded_creds_flagged(self, source_with_hardcoded_creds: Path) -> None:
        from ssdf_agent.skills.secure_defaults import check_secure_defaults
        result = check_secure_defaults(str(source_with_hardcoded_creds))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.pw9.hardcoded_credentials" in check_ids

    def test_debug_mode_flagged(self, source_with_debug: Path) -> None:
        from ssdf_agent.skills.secure_defaults import check_secure_defaults
        result = check_secure_defaults(str(source_with_debug))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.pw9.debug_enabled" in check_ids


class TestPO5SecureEnvironment:
    """Tests for PO.5 secure environment skill."""

    def test_root_user_flagged(self, source_with_root_dockerfile: Path) -> None:
        from ssdf_agent.skills.secure_environment import check_secure_environment
        result = check_secure_environment(str(source_with_root_dockerfile))
        check_ids = {f["check_id"] for f in result["findings"]}
        assert "ssdf.po5.root_user_container" in check_ids


class TestFindingStructure:
    """Tests for finding structure consistency."""

    def test_finding_has_required_fields(self, empty_source: Path) -> None:
        from ssdf_agent.skills.security_policy import check_security_policy
        result = check_security_policy(str(empty_source))
        for finding in result["findings"]:
            assert "severity" in finding
            assert "check_id" in finding
            assert "category" in finding
            assert "title" in finding
            assert "description" in finding
            assert "file_path" in finding
            assert "line_start" in finding
            assert "line_end" in finding
            assert "recommendation" in finding
