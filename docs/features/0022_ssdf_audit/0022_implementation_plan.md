# 0022 - NIST SP 800-218 SSDF v1.1 Audit Agent

## Overview

New audit agent for NIST SP 800-218 — Secure Software Development Framework (SSDF) Version 1.1 compliance. Unlike OWASP/CWE (code-level vulnerabilities), SSDF audits **development practices** — security policies, toolchain configs, CI/CD gates, code review processes, and vulnerability response workflows.

## SSDF Practice Groups

| Group | Practices | Description |
|-------|-----------|-------------|
| PO (Prepare Organization) | PO.1-PO.5 | Security policy, roles, toolchain, criteria, environment |
| PS (Protect Software) | PS.1-PS.3 | Code protection, release integrity, archive protection |
| PW (Produce Well-Secured Software) | PW.1-PW.9 | Secure design, deps, coding, build, review, testing, defaults |
| RV (Respond to Vulnerabilities) | RV.1-RV.3 | Vuln identification, remediation, root cause analysis |

## Architecture

Follows established agent pattern:
- `agents/ssdf/` — Python FastAPI microservice
- 19 skills across 4 practice groups
- Practice group composites aggregate skills (like SOC2 clauses)
- Prove strategy for staging verification
- Backend registration via config.go + launcher.go

## Skills (19 total)

- **PO**: security_policy, roles_governance, toolchain_check, security_criteria, secure_environment
- **PS**: code_protection, release_integrity, archive_protection
- **PW**: secure_design, dependency_reuse, secure_coding, build_security, code_review, security_testing, secure_defaults
- **RV**: vuln_identification, vuln_remediation, root_cause_analysis

## Integration Points

1. Backend config.go: `ssdf` agent entry on port 28007
2. Backend launcher.go: Local dev agent startup
3. docker-compose.yml: `agent-ssdf` service
4. config.ini: `agent_ssdf = 28007`
5. Makefile: SSDF test target
6. Prove strategies: `SsdfStrategy` registered
