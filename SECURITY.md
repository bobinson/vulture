# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| latest  | Yes                |
| < latest| No                 |

Only the latest release on the `main` branch receives security updates.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them responsibly via email:

**Email:** security@vulture.dev

### What to Include

- A description of the vulnerability and its potential impact.
- Steps to reproduce the issue or a proof-of-concept.
- The affected component(s) (backend, agents, frontend, CLI).
- The version or commit hash where the issue was observed.
- Any suggested fix or mitigation, if available.

### Response Timeline

| Stage           | Timeframe          |
|-----------------|--------------------|
| Acknowledgment  | Within 48 hours    |
| Assessment       | Within 7 days      |
| Fix release      | Depends on severity|

We will work with you to understand and validate the report. Critical and high-severity
issues will be prioritized for immediate remediation.

### Disclosure

We follow a coordinated disclosure process. We ask that you do not publicly disclose
the vulnerability until we have released a fix and provided a reasonable window for
users to update.

## Scope

The following components are in scope for security reports:

- Go backend (`backend/`)
- Python audit agents (`agents/`)
- Frontend application (`frontend/`)
- CLI tool (`cli/`)
- Docker and deployment configurations

## General Security Practices

- Never commit secrets, API keys, or credentials to the repository.
- Use the `.env.example` template for configuration; never commit `.env` files.
- Report any accidentally exposed credentials immediately.
