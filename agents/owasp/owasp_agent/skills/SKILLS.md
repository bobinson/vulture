# OWASP Security Auditor - Skills

Complete OWASP Top 10 (2021) coverage.

## injection_check (A03)
- **Function**: `check_injection(source_path: str) -> dict`
- **Purpose**: Detects SQL injection and command injection vulnerabilities
- **Severity**: critical
- **Detection**: f-string/format/sprintf in SQL queries, os.system(), eval(), exec(), unsafe subprocess calls

## auth_check (A07)
- **Function**: `check_authentication(source_path: str) -> dict`
- **Purpose**: Identifies weak authentication and missing auth on sensitive endpoints
- **Severity**: high
- **Detection**: MD5/SHA1 password hashing, hardcoded credentials, POST routes without auth decorators

## crypto_check (A02)
- **Function**: `check_cryptography(source_path: str) -> dict`
- **Purpose**: Finds weak cryptographic algorithms and hardcoded secrets
- **Severity**: high/critical
- **Detection**: DES, RC4, ECB mode, Math.random(), hardcoded API keys/tokens/passwords

## access_control (A01)
- **Function**: `check_access_control(source_path: str) -> dict`
- **Purpose**: Detects broken access control patterns (IDOR, missing authorization)
- **Severity**: high (medium with auth present)
- **Detection**: Direct use of request.args["id"], request.form["user_id"], r.URL.Query().Get()

## security_misconfig (A05)
- **Function**: `check_security_misconfig(source_path: str) -> dict`
- **Purpose**: Finds security misconfigurations (debug mode, exposed secrets, wildcard CORS)
- **Severity**: medium/high
- **Detection**: DEBUG=True, NODE_ENV=development, exposed DATABASE_URL, hardcoded SECRET_KEY, CORS wildcard origins

## insecure_design (A04)
- **Function**: `check_insecure_design(source_path: str) -> dict`
- **Purpose**: Detects insecure design patterns (auth endpoints without rate limiting)
- **Severity**: medium
- **Detection**: login/signin/signup/register/reset_password functions without project-level rate limiting

## vulnerable_components (A06)
- **Function**: `check_vulnerable_components(source_path: str) -> dict`
- **Purpose**: Identifies known-vulnerable dependency versions
- **Severity**: high
- **Detection**: Parses requirements.txt, package.json, go.mod; checks against known-vulnerable version thresholds (pyyaml<6.0, requests<2.31, django<4.2, flask<2.3, lodash<4.17.21, express<4.18)

## data_integrity (A08)
- **Function**: `check_data_integrity(source_path: str) -> dict`
- **Purpose**: Detects unsafe deserialization vulnerabilities
- **Severity**: critical
- **Detection**: pickle.load/loads, marshal.loads, shelve.open, yaml.load without SafeLoader, jsonpickle.decode, dill.loads

## logging_check (A09)
- **Function**: `check_logging(source_path: str) -> dict`
- **Purpose**: Finds sensitive data exposure in log statements
- **Severity**: high
- **Detection**: f-string log/print calls containing password, secret, token, api_key, credential variables

## ssrf_check (A10)
- **Function**: `check_ssrf(source_path: str) -> dict`
- **Purpose**: Detects Server-Side Request Forgery (SSRF) vulnerabilities
- **Severity**: high (medium in test files)
- **Detection**: requests.get/post/put/delete, urllib.request.urlopen, http.Get/Post, httpx.get/post with variable (non-literal) URL arguments
