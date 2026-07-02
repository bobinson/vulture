.PHONY: build build-backend build-agents build-agents-force build-frontend \
       test test-backend test-agents test-frontend \
       e2e coverage complexity lint \
       docker-up docker-down \
       gen-env config-check \
       verify verify-proofs verify-simulate verify-all \
       release-local install-local smoke-install smoke-negative freeze-deps check-lockfile \
       cwe-corpus cwe-corpus-full

# Build targets (parallel)
build:
	$(MAKE) -j3 build-backend build-agents build-frontend

build-backend:
	cd backend && go build -o bin/vulture ./cmd/vulture/

# `python -m pip` (not bare `pip`) so deps install into the SAME interpreter
# `make test` runs pytest with — bare `pip` can resolve to a different (e.g.
# system, PEP-668 externally-managed) Python, failing to install AND leaving the
# test interpreter missing deps like `pathspec`/`shared` → silent test failures.
#
# IDEMPOTENT: skip the (heavy) editable reinstall when the agents are already
# importable. test-agents depends on this, so a full reinstall on every `make
# test` would otherwise churn ~11 wheels concurrently with the parallel Go tests
# and flake the load-sensitive process tests (internal/localdev). Force a clean
# reinstall with `make build-agents-force` (e.g. after adding a dependency).
build-agents:
	@python -c "import shared, pathspec, chaos_agent" 2>/dev/null \
	  && echo "agents already installed (run 'make build-agents-force' to reinstall)" \
	  || $(MAKE) build-agents-force

build-agents-force:
	cd agents && python -m pip install -e shared/ -e chaos_engineering/ -e owasp/ -e soc2/ -e cwe/ -e prove/ -e xss/ -e ssdf/ -e discover/ -e do178c/ -e asvs/

build-frontend:
	cd frontend && npm ci && npm run build

# Test targets (parallel)
test:
	$(MAKE) -j3 test-backend test-agents test-frontend

test-backend:
	cd backend && go test ./...

# Depends on build-agents: the agents import each other (e.g. chaos_agent imports
# `shared`), so they must be installed editable in the test interpreter first.
# Without it, cross-package imports fail at collection ("No module named 'shared'").
test-agents: build-agents
	cd agents/shared && python -m pytest tests/unit/ -v
	cd agents/chaos_engineering && python -m pytest tests/unit/ -v
	cd agents/owasp && python -m pytest tests/unit/ -v
	cd agents/soc2 && python -m pytest tests/unit/ -v
	cd agents/cwe && python -m pytest tests/unit/ -v
	cd agents/prove && python -m pytest tests/unit/ -v
	cd agents/xss && python -m pytest tests/unit/ -v
	cd agents/ssdf && python -m pytest tests/unit/ -v
	cd agents/discover && python -m pytest tests/unit/ -v
	cd agents/do178c && python -m pytest tests/unit/ -v
	cd agents/asvs && python -m pytest tests/unit/ -v

test-frontend:
	cd frontend && npm test

# E2E tests
e2e:
	cd backend && go test ./test/e2e/ -v -tags=e2e
	cd agents/shared && python -m pytest tests/e2e/ -v
	cd agents/chaos_engineering && python -m pytest tests/e2e/ -v
	cd agents/owasp && python -m pytest tests/e2e/ -v
	cd agents/soc2 && python -m pytest tests/e2e/ -v
	cd agents/cwe && python -m pytest tests/e2e/ -v
	cd agents/prove && python -m pytest tests/e2e/ -v
	cd agents/xss && python -m pytest tests/e2e/ -v
	cd agents/ssdf && python -m pytest tests/e2e/ -v
	cd agents/discover && python -m pytest tests/e2e/ -v
	cd agents/do178c && python -m pytest tests/e2e/ -v
	cd agents/asvs && python -m pytest tests/e2e/ -v
	cd frontend && npx playwright test

# Coverage verification (100% required)
coverage:
	cd backend && go test ./... -coverprofile=coverage.out -covermode=atomic && \
		go tool cover -func=coverage.out | grep total | awk '{print $$3}' | grep -q "100.0%"
	cd agents && python -m pytest tests/ --cov=. --cov-report=term --cov-fail-under=100
	cd frontend && npm test -- --coverage --coverageThreshold='{"global":{"lines":100,"branches":100,"functions":100,"statements":100}}'

# Complexity verification (< 10)
complexity:
	@cd backend && RESULT=$$(gocyclo -over 9 .); if [ -n "$$RESULT" ]; then echo "$$RESULT"; echo "FAIL: functions exceed cyclomatic complexity 10"; exit 1; fi; echo "Go complexity OK"
	cd agents && radon cc . -a -nc && echo "Python complexity OK"

# Lint
lint:
	cd backend && golangci-lint run ./...
	cd agents && ruff check .
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

# Interpreter: prefer the project venv (agents/.venv — the canonical local test
# interpreter, has openai-agents/shared installed) when present; otherwise fall
# back to bare `python` (the interpreter CI populates via its editable installs
# in the test-agents job). Resolved here so both lanes share one definition.
CWE_CORPUS_PY := $(shell if [ -x agents/.venv/bin/python ]; then echo $(CURDIR)/agents/.venv/bin/python; else echo python; fi)

# PR lane: run the curated subset deterministically + fail on a stale golden.
# Fast (<~60s) and deterministic — safe for every PR.
cwe-corpus:
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) corpus_runner.py --fragments $(CWE_CORPUS_FRAGMENTS)
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) report_coverage.py --check

# Nightly / label lane: the FULL deterministic sweep (every production fragment,
# Juliet included once vendored) + the stale-golden gate. Slower; never on PRs.
cwe-corpus-full:
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) corpus_runner.py
	cd $(CWE_CORPUS_DIR) && $(CWE_CORPUS_PY) report_coverage.py --check
