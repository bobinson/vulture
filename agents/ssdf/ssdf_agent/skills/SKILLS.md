# SSDF Agent Skills

NIST SP 800-218 SSDF v1.1 compliance audit skills. Each skill maps to one or more SSDF practices.

## PO - Prepare the Organization

### security_policy (PO.1)
- **Practice**: PO.1 - Define Security Requirements
- **Detection**: Scans for SECURITY.md, SECURITY.txt, .github/SECURITY.md; checks README/CONTRIBUTING for policy references
- **check_ids**: `ssdf.po1.missing_security_policy`
- **Severity**: medium

### roles_governance (PO.2)
- **Practice**: PO.2 - Implement Roles & Responsibilities
- **Detection**: Scans for CODEOWNERS, MAINTAINERS.md, .github/CODEOWNERS
- **check_ids**: `ssdf.po2.missing_codeowners`
- **Severity**: medium

### toolchain_check (PO.3)
- **Practice**: PO.3 - Implement Supporting Toolchains
- **Detection**: Scans CI workflows for SAST (semgrep, codeql, snyk, bandit, gosec), DAST (ZAP, nuclei, nikto), and SCA (dependabot.yml, renovate.json, .snyk)
- **check_ids**: `ssdf.po3.no_sast_tool`, `ssdf.po3.no_dast_tool`, `ssdf.po3.no_sca_tool`
- **Severity**: high (SAST/SCA), medium (DAST)

### security_criteria (PO.4)
- **Practice**: PO.4 - Define & Use Criteria for Software Security Checks
- **Detection**: Scans CI for quality gates (required_status_checks, branch_protection); checks for PR templates
- **check_ids**: `ssdf.po4.no_quality_gates`, `ssdf.po4.no_merge_policy`
- **Severity**: medium, low

### secure_environment (PO.5)
- **Practice**: PO.5 - Implement & Maintain Secure Environments
- **Detection**: Scans for secrets management (Vault, AWS Secrets Manager, SOPS); checks Dockerfiles for root user; checks docker-compose for privileged mode
- **check_ids**: `ssdf.po5.no_secrets_management`, `ssdf.po5.privileged_container`, `ssdf.po5.root_user_container`
- **Severity**: medium (secrets), high (privileged/root)

## PS - Protect the Software

### code_protection (PS.1)
- **Practice**: PS.1 - Protect All Forms of Code
- **Detection**: Scans for pre-commit hooks (.pre-commit-config.yaml, husky, lint-staged); checks for commit signing configs
- **check_ids**: `ssdf.ps1.no_pre_commit_hooks`, `ssdf.ps1.no_commit_signing`
- **Severity**: medium, low

### release_integrity (PS.2)
- **Practice**: PS.2 - Provide a Mechanism for Verifying Release Integrity
- **Detection**: Scans CI for signing (cosign, sigstore, GPG), checksums (sha256sum), and provenance (SLSA, in-toto)
- **check_ids**: `ssdf.ps2.no_release_signing`, `ssdf.ps2.no_checksums`, `ssdf.ps2.no_provenance`
- **Severity**: medium, low

### archive_protection (PS.3)
- **Practice**: PS.3 - Archive & Protect Each Release
- **Detection**: Scans for automated release workflows (GitHub releases, goreleaser, semantic-release)
- **check_ids**: `ssdf.ps3.no_release_archive`
- **Severity**: low

## PW - Produce Well-Secured Software

### secure_design (PW.1 + PW.2)
- **Practice**: PW.1 - Design Software to Meet Security Requirements, PW.2 - Review the Software Design
- **Detection**: Scans for threat model docs, design/architecture docs, design review references in PR templates
- **check_ids**: `ssdf.pw1.no_threat_model`, `ssdf.pw2.no_design_review`
- **Severity**: medium, low

### dependency_reuse (PW.4)
- **Practice**: PW.4 - Reuse Existing Well-Secured Software
- **Detection**: Scans for lock files (package-lock.json, go.sum, poetry.lock, etc.); checks for unpinned versions (* or latest)
- **check_ids**: `ssdf.pw4.no_lock_file`, `ssdf.pw4.unpinned_dependencies`
- **Severity**: high, medium

### secure_coding (PW.5)
- **Practice**: PW.5 - Create Source Code by Following Secure Coding Practices
- **Detection**: Scans for linter configs (.eslintrc, ruff.toml, .golangci.yml, etc.)
- **check_ids**: `ssdf.pw5.no_linter_config`
- **Severity**: medium

### build_security (PW.6)
- **Practice**: PW.6 - Configure the Compilation, Interpreter, and Build Processes
- **Detection**: Checks Dockerfiles for minimal base images (slim, alpine, distroless)
- **check_ids**: `ssdf.pw6.no_minimal_base_image`
- **Severity**: low

### code_review (PW.7)
- **Practice**: PW.7 - Review and/or Analyze Human-Readable Code
- **Detection**: Scans for PR templates; checks CI/CODEOWNERS for required reviewers
- **check_ids**: `ssdf.pw7.no_pr_template`, `ssdf.pw7.no_required_reviews`
- **Severity**: medium

### security_testing (PW.8)
- **Practice**: PW.8 - Test Executable Code
- **Detection**: Scans for security test files, fuzz testing configs, coverage enforcement in CI
- **check_ids**: `ssdf.pw8.no_security_tests`, `ssdf.pw8.no_fuzz_tests`, `ssdf.pw8.no_coverage_gate`
- **Severity**: medium, low

### secure_defaults (PW.9)
- **Practice**: PW.9 - Configure Software to Have Secure Settings by Default
- **Detection**: Scans code for hardcoded credentials, debug mode flags, permissive CORS; excludes comments, imports, scanner definitions, and env variable reads
- **check_ids**: `ssdf.pw9.hardcoded_credentials`, `ssdf.pw9.debug_enabled`, `ssdf.pw9.permissive_cors`
- **Severity**: critical (credentials), medium (debug/CORS)

## RV - Respond to Vulnerabilities

### vuln_identification (RV.1)
- **Practice**: RV.1 - Identify & Confirm Vulnerabilities
- **Detection**: Scans for dependency scanning (dependabot, renovate, snyk, trivy, grype) in CI; checks for container scanning when Dockerfiles present
- **check_ids**: `ssdf.rv1.no_vuln_scanning`, `ssdf.rv1.no_container_scanning`
- **Severity**: high, medium

### vuln_remediation (RV.2)
- **Practice**: RV.2 - Assess, Prioritize, and Remediate Vulnerabilities
- **Detection**: Scans for security issue templates; checks security docs for patching SLA/timeline
- **check_ids**: `ssdf.rv2.no_security_issue_template`, `ssdf.rv2.no_patching_sla`
- **Severity**: low

### root_cause_analysis (RV.3)
- **Practice**: RV.3 - Analyze Vulnerabilities to Identify Root Causes
- **Detection**: Scans for post-mortem/incident templates; checks docs for RCA process documentation
- **check_ids**: `ssdf.rv3.no_postmortem_template`, `ssdf.rv3.no_rca_process`
- **Severity**: low
