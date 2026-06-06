.PHONY: build build-backend build-agents build-frontend \
       test test-backend test-agents test-frontend \
       e2e coverage complexity lint \
       docker-up docker-down \
       gen-env config-check \
       verify verify-proofs verify-simulate verify-all \
       release-local install-local smoke-install smoke-negative freeze-deps check-lockfile

# Build targets (parallel)
build:
	$(MAKE) -j3 build-backend build-agents build-frontend

build-backend:
	cd backend && go build -o bin/vulture ./cmd/vulture/

# Use `python -m pip` (not bare `pip`) so deps install into the SAME interpreter
# that `make test` runs pytest with. Bare `pip` can resolve to a different
# (e.g. system, PEP-668 externally-managed) Python, which both fails to install
# and leaves the test interpreter missing deps like `pathspec` → silent
# file-scanner test failures. Run `make build-agents` before `make test`.
build-agents:
	cd agents && python -m pip install -e shared/ -e chaos_engineering/ -e owasp/ -e soc2/ -e cwe/ -e prove/ -e xss/ -e ssdf/ -e discover/ -e do178c/ -e asvs/

build-frontend:
	cd frontend && npm ci && npm run build

# Test targets (parallel)
test:
	$(MAKE) -j3 test-backend test-agents test-frontend

test-backend:
	cd backend && go test ./...

test-agents:
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
