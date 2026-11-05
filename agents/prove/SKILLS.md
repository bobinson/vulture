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
7. **Evidence privacy**: proof evidence and stream messages never carry exception text or repository content. A probe or pipeline failure is reported as a fixed category plus the exception class, for example `connection refused (ConnectError)` or `handshake rejected (InvalidStatus, HTTP 403)`. The categories are name resolution failed, TLS handshake failed, connection refused, timed out, handshake rejected, protocol error, connection failed and internal error. The full, secret-redacted detail goes to the server log only. Every emitted text field is also scrubbed of the strings the agent showed the model: the finding's path becomes `[source file]`, its quoted code lines become `[source excerpt]`, the scan root becomes `[source root]`, and secret-shaped values are masked. `finding_id`, `status` and the configured `staging_url` are left unchanged. The scrub runs before incremental discovery collects routes from attempt evidence, so no repository path is ever requested from the target. Every emitter in a run scrubs the strings of EVERY finding in that run, not only the finding being proved, because cross-finding learnings are shared by all later plan prompts. A failure raised through a task group (`ExceptionGroup`) is categorised by its members. Timeout evidence is scrubbed before it is cut to 200 characters, and the cut never splits a placeholder. The scrub also catches a path that is percent-encoded, written with Windows separators, or placed under a different root, a quoted line whose whitespace was changed, and any other file under the scan root (it becomes `[source root]`). It also catches a path in any letter case or percent-encoded twice (`%252F`), a sibling directory of the scan root, and any contiguous fragment of a quoted code line that is at least 24 characters long, holds 2 identifiers and contains code syntax (one of `( ) [ ] { } = ;`), even with reflowed whitespace or JSON-escaped quotes. A bare string literal from the code (an error message) is not removed: when a finding reproduces, the target returns that literal, and it is the proof. Whatever JSON shape the model answers with (array, object, nested value, number or null), every emitted text field is a single scrubbed string; a list or object is flattened to its leaves joined by `; `. Target content is not repository content. On a URL of the configured staging target, and on a route the agent actually requested, a finding's bare file name (`backup.sql`, `main.js`, `package.json`) is kept and the staging host is never absorbed into a placeholder, so verified evidence keeps its reproducing endpoint; a multi-component repository path is removed everywhere, including inside a staging URL. Its cost does not grow with the number of findings: markers are indexed by their rarest identifier token, and code lines by their identifier pairs, ignoring pairs shared by more than 64 lines (idioms such as `if err`). Known limits, which are not caught: a paraphrase of the code; a code fragment below that floor or without code syntax; a fragment made only of idiom pairs; the directory or the extensionless form of a path on its own (these are left alone on purpose, because a target route often has the same shape, such as `/api/billing/`); a path written with look-alike separators (`∕`) or spaced out (`src / payments / x.go`), of which only the file name is removed; another repository file the agent never showed the model; a path under the scan root's parent directory that does not start with the scan root's own name (the parent directory, including any user name in it, is kept); and a secret shape the shared `mask_secret_values` does not recognise, such as `password=<plain word>`.

## Verification Statuses

| Status | Meaning |
|--------|---------|
| `verified` | Finding was reproduced with evidence |
| `not_reproduced` | Finding could not be reproduced (potential false positive) |
| `inconclusive` | Verification attempts were not conclusive |
| `skipped` | Plan was deemed unsafe by safety review |
