.PHONY: build build-backend build-agents build-frontend \
       test test-backend test-agents test-frontend \
       e2e coverage complexity lint \
       docker-up docker-down

# Build targets
build: build-backend build-agents build-frontend

build-backend:
	cd backend && go build -o bin/vulture ./cmd/vulture/

build-agents:
	cd agents && pip install -r requirements.txt

build-frontend:
	cd frontend && npm ci && npm run build

# Test targets
test: test-backend test-agents test-frontend

test-backend:
	cd backend && go test ./...

test-agents:
	cd agents/shared && python -m pytest tests/unit/ -v
	cd agents/chaos_engineering && python -m pytest tests/unit/ -v
	cd agents/owasp && python -m pytest tests/unit/ -v
	cd agents/soc2 && python -m pytest tests/unit/ -v

test-frontend:
	cd frontend && npm test

# E2E tests
e2e:
	cd backend && go test ./test/e2e/ -v -tags=e2e
	cd agents && python -m pytest tests/e2e/ -v
	cd frontend && npx playwright test

# Coverage verification (100% required)
coverage:
	cd backend && go test ./... -coverprofile=coverage.out -covermode=atomic && \
		go tool cover -func=coverage.out | grep total | awk '{print $$3}' | grep -q "100.0%"
	cd agents && python -m pytest tests/ --cov=. --cov-report=term --cov-fail-under=100
	cd frontend && npm test -- --coverage --coverageThreshold='{"global":{"lines":100,"branches":100,"functions":100,"statements":100}}'

# Complexity verification (< 10)
complexity:
	cd backend && gocyclo -over 9 . && echo "Go complexity OK"
	cd agents && radon cc . -a -nc && echo "Python complexity OK"

# Lint
lint:
	cd backend && golangci-lint run ./...
	cd agents && ruff check .
	cd frontend && npm run lint

# Docker
docker-up:
	docker compose up -d --build

docker-down:
	docker compose down
