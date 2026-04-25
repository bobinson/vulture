.PHONY: build build-backend build-agents build-frontend \
       test test-backend test-agents test-frontend \
       e2e coverage complexity lint \
       docker-up docker-down \
       gen-env config-check \
       verify verify-proofs verify-simulate verify-all

# Build targets (parallel)
build:
	$(MAKE) -j3 build-backend build-agents build-frontend

build-backend:
	cd backend && go build -o bin/vulture ./cmd/vulture/

build-agents:
	cd agents && pip install -e shared/ -e chaos_engineering/ -e owasp/ -e soc2/ -e cwe/ -e prove/ -e xss/ -e ssdf/ -e discover/ -e do178c/ -e asvs/

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
