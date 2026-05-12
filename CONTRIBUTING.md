# Contributing to Vulture

Thank you for your interest in contributing to Vulture! This guide will help you get started.

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

1. **Fork** the repository on GitHub.
2. **Create a branch** from `main` for your change (`git checkout -b feature/my-change`).
3. **Make your changes** following the development workflow and code quality rules below.
4. **Push** your branch and open a **Pull Request** against `main`.

## Development Setup

### Prerequisites

- Go 1.24+
- Python 3.12+
- Node.js 22+
- Docker and Docker Compose

### Getting Started

```bash
# Clone your fork
git clone https://github.com/<your-user>/vulture.git
cd vulture

# Copy the configuration template and generate .env
cp config.ini.example config.ini
# Edit config.ini — at minimum set database.password
make gen-env

# Start all services
make docker-up

# Or run components individually for development:
make build          # Build all components
make test           # Run all tests
make lint           # Lint all components
```

## Development Workflow

Every change must follow this sequence:

1. **Understand** the problem fully before writing code.
2. **Plan** the approach and identify affected components.
3. **Write E2E tests first** that define the expected behavior.
4. **Implement** the code to make the tests pass.
5. **Verify** by running the full test suite after every change.

**Critical rule:** Never modify E2E business logic tests to make code pass. The tests define the business contract. If tests fail, fix the implementation.

## Code Quality Requirements

- **Tests required**: 100% test coverage. Every line of code must be covered.
- **Cyclomatic complexity**: No function may exceed a cyclomatic complexity of 10.
- **DRY**: No duplicated logic. Extract shared code into appropriate modules.
- **Linting**: All code must pass linting (`golangci-lint` for Go, `ruff` for Python, `eslint` for TypeScript).

### Running Quality Checks

```bash
make test           # All tests (Go + Python + Frontend)
make e2e            # E2E test suites
make coverage       # Verify test coverage
make complexity     # Verify cyclomatic complexity
make lint           # Lint all components
```

## Language-Specific Guidelines

### Go (backend/)

- Use the standard library where possible; minimize dependencies.
- Return errors with context: `fmt.Errorf("operation: %w", err)`.
- All handlers accept service interfaces; all services accept repository interfaces.

### Python (agents/)

- Type hints on all functions.
- Each agent must have a `SKILLS.md` documenting its capabilities.
- Use `run_combined_audit()` from `shared.audit_runner` for audit pipelines.

### Frontend (frontend/)

- React 19 with TypeScript strict mode.
- Tailwind CSS v4 for styling.
- Use `react-i18next` for all user-facing strings (supports en, es, de, fr, ja, pt).

## Pull Request Checklist

Before submitting your PR, verify:

- [ ] All tests pass (`make test`)
- [ ] Lint is clean (`make lint`)
- [ ] Cyclomatic complexity is within limits (`make complexity`)
- [ ] New code has test coverage (`make coverage`)
- [ ] Documentation is updated if behavior changed
- [ ] Commit messages are clear and descriptive
- [ ] E2E business logic tests were not modified to make code pass

## Adding a New Audit Agent

To add a new audit type (e.g., GDPR):

1. Create `agents/gdpr/` from an existing agent template.
2. Add one line to the Go agent registry in `internal/config/config.go`.
3. Add one service block to `docker-compose.yml`.
4. The frontend auto-discovers the new agent via `GET /api/agents`.

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests.
- Include steps to reproduce, expected behavior, and actual behavior.
- For security vulnerabilities, see [SECURITY.md](SECURITY.md) instead.

## Test fixtures: synthetic credentials

Several test files contain strings that look like real secrets but are
**deliberate synthetic test fixtures** used to exercise Vulture's own
secret-scanning skills. These are safe — and required for the detector
tests to be meaningful — but may trip third-party secret scanners
running against the repository. Specifically:

- `agents/cwe/tests/unit/skills/secret_scan/` — uses `AKIAJABCDEFGHIJKLMN0`
  and `AKIAIOSFODNN7EXAMPLE` (Amazon's documented example value).
- `agents/cwe/tests/unit/skills/secret_scan/test_pem_blocks.py` —
  `-----BEGIN RSA PRIVATE KEY-----` blocks with literal `"fake"` /
  sentinel-text bodies.
- `backend/pkg/gitutil/clone_test.go` — `-----BEGIN OPENSSH PRIVATE KEY-----`
  with `"fake"` body.
- `verification/simulated-target/source/app.py` — `DB_PASSWORD = "admin123"`
  is the deliberately-vulnerable target used by formal-verification
  proofs.

If you add a new secret-scanning detector test that needs realistic
credential shapes, follow this same pattern: use sentinel bodies
(`fake`, `EXAMPLE`, all-zeros) or AWS's documented example identifiers.
Never commit a real key, even a revoked one.

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
