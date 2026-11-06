.PHONY: build build-backend build-agents build-agents-dev build-frontend \
       test test-backend test-race test-agents test-frontend test-mcp \
       e2e coverage complexity lint \
       docker-up docker-down \
       gen-env config-check \
       verify verify-proofs verify-simulate verify-all \
       release-local install-local smoke-install smoke-negative freeze-deps check-lockfile \
       cwe-corpus cwe-corpus-full build-tools

# Build targets (parallel)
build:
	$(MAKE) -j3 build-backend build-agents build-frontend

build-backend:
	cd backend && go build -o bin/vulture ./cmd/vulture/

# Python environments come only from the hashed lockfiles, through
# scripts/locked-venv.sh (its header says why): make never runs pip itself. Each
# venv is rebuilt when its lockfile changes and left alone otherwise, so `make
# test` reinstalls nothing while the parallel Go tests run. The first-party
# packages load from the checkout, so a code change needs no rebuild.
#   agents/.venv      the runtime set the launcher runs (build-agents, via build.sh)
#   agents/.venv-dev  the same pins plus the agents' test tools (the test targets)
#   mcp/.venv         vulture-mcp's dependencies plus its test tools (test-mcp)
#   .venv-tools       ruff and pip-audit (build-tools; lint, and CI's lint and audits)
AGENT_DIRS := $(patsubst %/pyproject.toml,%,$(wildcard agents/*/pyproject.toml))
AGENTS_DEV_PY := $(CURDIR)/agents/.venv-dev/bin/python

build-agents:
	scripts/build.sh agents

build-agents-dev:
	scripts/locked-venv.sh agents/.venv-dev agents/requirements-dev-frozen.txt $(AGENT_DIRS)

build-tools:
	scripts/locked-venv.sh .venv-tools scripts/requirements-tools-frozen.txt

build-frontend:
	cd frontend && npm ci && npm run build

# Test targets (parallel)
test:
	$(MAKE) -j3 test-backend test-agents test-frontend test-mcp

test-backend:
	cd backend && go test ./...

# MCP server tests in mcp/.venv, built from mcp/requirements-dev-frozen.txt:
# vulture-mcp needs the mcp SDK 1.x, and the agents' set pins 2.x.
MCP_PY := $(CURDIR)/mcp/.venv/bin/python
test-mcp:
	scripts/locked-venv.sh mcp/.venv mcp/requirements-dev-frozen.txt mcp
	cd mcp && $(MCP_PY) -m pytest tests/ -q

# Race detector on the concurrency-bearing packages. Feature 0071 added a
# per-audit event broadcaster with a fan-out goroutine per subscriber; none of
# its failure modes (lost history/tail seam, subscriber map races) are visible to
# a non-race run, so this is a separate gate rather than a flag on test-backend
# (which would roughly triple the whole suite's runtime).
test-race:
	cd backend && go test -race ./internal/handler/... ./internal/service/... ./internal/agui/...

# Runs in agents/.venv-dev: the agents import each other (e.g. chaos_agent imports
# `shared`), and that venv loads every agent package from the checkout. Without
# it, cross-package imports fail at collection ("No module named 'shared'").
test-agents: build-agents-dev
	cd agents/shared && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/chaos_engineering && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/owasp && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/soc2 && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/cwe && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/prove && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/xss && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/ssdf && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/discover && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/do178c && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v
	cd agents/asvs && $(AGENTS_DEV_PY) -m pytest tests/unit/ -v

test-frontend:
	cd frontend && npm test

# E2E tests
e2e: build-agents-dev
	cd backend && go test ./test/e2e/ -v -tags=e2e
	cd agents/shared && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/chaos_engineering && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/owasp && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/soc2 && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/cwe && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/prove && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/xss && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/ssdf && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/discover && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/do178c && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd agents/asvs && $(AGENTS_DEV_PY) -m pytest tests/e2e/ -v
	cd frontend && npx playwright test

# Coverage verification (100% required)
coverage: build-agents-dev
	cd backend && go test ./... -coverprofile=coverage.out -covermode=atomic && \
		go tool cover -func=coverage.out | grep total | awk '{print $$3}' | grep -q "100.0%"
	cd agents && $(AGENTS_DEV_PY) -m pytest tests/ --cov=. --cov-report=term --cov-fail-under=100
	cd frontend && npm test -- --coverage --coverageThreshold='{"global":{"lines":100,"branches":100,"functions":100,"statements":100}}'

# Complexity verification (< 10)
complexity:
	@cd backend && RESULT=$$(gocyclo -over 9 .); if [ -n "$$RESULT" ]; then echo "$$RESULT"; echo "FAIL: functions exceed cyclomatic complexity 10"; exit 1; fi; echo "Go complexity OK"
	cd agents && radon cc . -a -nc && echo "Python complexity OK"

# Lint
lint: build-tools
	cd backend && golangci-lint run ./...
	cd agents && $(CURDIR)/.venv-tools/bin/ruff check .
	cd frontend && npm run lint

# Config: generate .env from config.ini
gen-env:
	@bash scripts/gen-env.sh config.ini .env

config-check:
	@test -f config.ini || (echo "ERROR: config.ini not found at project root" && exit 1)
	@bash scripts/gen-env.sh config.ini /tmp/vulture-config-check.env && echo "config.ini OK"

# Docker (gen-env runs first to ensure .env is fresh)
docker-up: gen-env
	docker build -t vulture-agent-base:latest -f agents/Dockerfile.base agents/
	docker compose up -d --build

docker-down:
	docker compose down

# Formal verification (independent of app code)
verify:
	$(MAKE) -C verification conformance

verify-proofs:
	$(MAKE) -C verification check-proofs

verify-simulate:
	$(MAKE) -C verification simulate

verify-agents:
	$(MAKE) -C verification agent-verify

verify-all:
	$(MAKE) -C verification all

# ─── Feature 0044: native installer (Mode E) ─────────────────────────────
# Build a per-platform installer tarball using the current host's OS/arch.
release-local:
	scripts/build-release.sh v0.0.0-dev

# Build a tarball and install it into a temp VULTURE_HOME for testing.
install-local: release-local
	bash -c 'tb=$$(ls dist/vulture-*-$$(uname -s | tr A-Z a-z)-*.tar.gz | head -1); \
	         scripts/smoke-install.sh "$$tb"'

# Run the smoke + negative tests as a single make target.
smoke-install:
	scripts/build-release.sh v0.0.0-dev
	bash -c 'tb=$$(ls dist/vulture-*.tar.gz | head -1); scripts/smoke-install.sh "$$tb"'

smoke-negative:
	scripts/smoke-negative.sh

# Re-generate the single hash-pinned agent lockfile (feature 0055 B1).
# Aggregates third-party deps across the agents' pyprojects (first-party
# vulture-* excluded; they load via PYTHONPATH) into agents/requirements-frozen.txt.
# UPGRADE=1 refreshes to latest in-range; UPGRADE_PKG=<name> bumps one.
freeze-deps:
	@if [ -n "$(UPGRADE_PKG)" ]; then scripts/gen-lockfile.sh --upgrade-pkg "$(UPGRADE_PKG)"; \
	 elif [ "$(UPGRADE)" = "1" ]; then scripts/gen-lockfile.sh --upgrade; \
	 else scripts/gen-lockfile.sh; fi

# Fail if the committed lockfile is stale (CI + vulture.sh release gate).
check-lockfile:
	scripts/check-lockfile.sh

# ─── Feature 0057 Phase 5e (R17): CWE corpus gate lanes ──────────────────
# The corpus runner is DETERMINISTIC (regex skills + signatures, NO live LLM).
#
# CWE_CORPUS_FRAGMENTS is the CURATED PR subset: the signature + skill manifest
# fragments only. It is an EXPLICIT list (passed via `--fragments`) so the PR
# lane stays pinned and fast (<~60s) — a future full-Juliet fragment dropped
# into manifest.d/ does NOT silently leak onto the PR lane (R17: full Juliet,
# 64,295 cases, MUST NOT hit the PR lane; it runs on the nightly lane only).
# The `_golden` slice is excluded (it backs the unit tests, never production N).
CWE_CORPUS_FRAGMENTS := injection sig_a sig_b signatures_a signatures_b skill_c
CWE_CORPUS_DIR := agents/cwe/tests/corpus

# Interpreter: agents/.venv-dev, as for the agent tests (locally and in CI).
CWE_CORPUS_PY := $(AGENTS_DEV_PY)

# PR lane: run the curated subset deterministically + fail on a stale golden.
# Fast (<~60s) and deterministic — safe for every PR.
cwe-corpus: build-agents-dev
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) corpus_runner.py --fragments $(CWE_CORPUS_FRAGMENTS)
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) report_coverage.py --check

# Nightly / label lane: the FULL deterministic sweep (every production fragment,
# Juliet included once vendored) + the stale-golden gate. Slower; never on PRs.
cwe-corpus-full: build-agents-dev
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) corpus_runner.py
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) report_coverage.py --check
