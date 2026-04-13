# Prove Agent Skills

The Prove agent autonomously verifies scanner findings against a staging environment using a Plan-Review-Execute loop.

## Verification Strategies

### owasp_verification (OWASP Security)
- **Function**: `OwaspStrategy.plan/review/execute`
- **Purpose**: Verify OWASP security findings (injection, auth bypass, XSS, CSRF, etc.) by crafting and sending HTTP probes to the staging environment
- **Plan**: LLM generates HTTP request targeting the vulnerable endpoint with a test payload
- **Review**: LLM checks the plan won't cause data corruption or denial of service
- **Execute**: Sends HTTP request, LLM analyzes response for vulnerability indicators
- **Severity**: Inherits from original finding

### chaos_verification (Chaos Engineering)
- **Function**: `ChaosStrategy.plan/review/execute`
- **Purpose**: Verify missing resilience patterns (retry, circuit breaker, timeout, fallback) by probing endpoint behavior under stress
- **Plan**: LLM designs an HTTP test that reveals missing resilience (e.g., timeout test, concurrent request test)
- **Review**: LLM ensures the test won't cause cascading failures
- **Execute**: Sends HTTP request, LLM analyzes response for resilience gaps
- **Severity**: Inherits from original finding

### soc2_verification (SOC2 Compliance)
- **Function**: `Soc2Strategy.plan/review/execute`
- **Purpose**: Verify SOC2 compliance gaps (access controls, audit logging, encryption) by checking staging configuration
- **Plan**: LLM identifies HTTP endpoint or header to check for compliance indicator
- **Review**: LLM ensures the test only reads configuration, doesn't modify anything
- **Execute**: Sends HTTP request, LLM analyzes response for compliance gaps
- **Severity**: Inherits from original finding

### cwe_verification (CWE Weaknesses)
- **Function**: `CweStrategy.plan/review/execute`
- **Purpose**: Verify CWE-mapped vulnerabilities by crafting targeted test vectors
- **Plan**: LLM maps CWE ID to concrete HTTP test payload
- **Review**: LLM ensures the test payload is controlled and won't cause damage
- **Execute**: Sends HTTP request with crafted input, LLM analyzes response
- **Severity**: Inherits from original finding

## Safety Mechanisms

1. **Staging URL validation**: Refuses localhost/local IPs unless `--allow-local` is set
2. **LLM safety review**: Every plan is reviewed before execution; unsafe plans are skipped
3. **Iteration limit**: Default 3, maximum 10 attempts per finding
4. **HTTP-only**: All verification uses HTTP requests only; no shell commands or file writes
5. **Request timeout**: 10 seconds per HTTP request
6. **Circuit breaker**: 3 consecutive failures aborts remaining findings for that strategy

## Verification Statuses

| Status | Meaning |
|--------|---------|
| `verified` | Finding was reproduced with evidence |
| `not_reproduced` | Finding could not be reproduced (potential false positive) |
| `inconclusive` | Verification attempts were not conclusive |
| `skipped` | Plan was deemed unsafe by safety review |
