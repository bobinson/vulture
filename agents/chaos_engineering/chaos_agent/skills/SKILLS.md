# Chaos Engineering Auditor - Skills

## retry_analysis
- **Function**: `check_retry_patterns(source_path: str) -> dict`
- **Purpose**: Detects HTTP/RPC calls lacking retry logic with exponential backoff
- **Severity**: high
- **Detection**: Scans for HTTP client calls (requests, net/http, fetch, axios) without retry patterns (tenacity, backoff, Retry)

## circuit_breaker
- **Function**: `check_circuit_breaker(source_path: str) -> dict`
- **Purpose**: Identifies external service calls without circuit breaker protection
- **Severity**: medium
- **Detection**: Scans for HTTP/gRPC calls without circuit breaker libraries (pybreaker, gobreaker, resilience4j)

## timeout_analysis
- **Function**: `check_timeout_handling(source_path: str) -> dict`
- **Purpose**: Finds network operations missing explicit timeout configuration
- **Severity**: high
- **Detection**: Scans for network calls (HTTP, DB, socket) without timeout parameters or context deadlines

## fallback_analysis
- **Function**: `check_fallback_patterns(source_path: str) -> dict`
- **Purpose**: Detects failure-prone operations without fallback or degraded response mechanisms
- **Severity**: medium
- **Detection**: Scans for external calls/queries without fallback patterns (cached defaults, graceful degradation)

## blast_radius
- **Function**: `assess_blast_radius(source_path: str) -> dict`
- **Purpose**: Assesses shared state usage without isolation (bulkhead) patterns
- **Severity**: medium
- **Detection**: Scans for global/shared state, singletons, shared databases without rate limiting, semaphores, or namespace isolation
