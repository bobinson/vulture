# CWE Weakness Auditor - Skills

Analyzes source code for Common Weakness Enumeration (CWE v4.19.1) vulnerabilities across 17 categories covering 846 software-relevant CWE IDs with catalog-driven detection, self-learning confidence scoring, and MMR-based memory retrieval with embedding similarity.

## injection_check

- **Function**: `check_injection(source_path: str) -> dict`
- **Purpose**: Detects code injection vulnerabilities across SQL, OS command, XSS, dynamic code execution, and SSRF
- **CWE Coverage**:
  - **CWE-89** SQL Injection: f-string/format SQL queries, Sprintf-based queries
  - **CWE-78** OS Command Injection: `os.system()`, `os.popen()`, `subprocess` with `shell=True`
  - **CWE-79** Cross-Site Scripting: `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`
  - **CWE-94** Code Injection: `eval()`, `exec()`, `new Function()`, string-based `setTimeout`/`setInterval`
  - **CWE-918** Server-Side Request Forgery (SSRF): `requests.get(user_input)`, `urllib.request.urlopen(user_input)`, `http.Get(user_input)`, `fetch(user_input)`
- **Severity**: critical (CWE-89, CWE-78, CWE-94), high (CWE-79, CWE-918)
- **Detection**: Regex pattern matching with safe-call exclusions (static string arguments, import lines, URL allowlists)
- **Catalog Enrichment**: All findings enriched with CWE catalog metadata (name, likelihood, mitigation)

## buffer_check

- **Function**: `check_buffer_handling(source_path: str) -> dict`
- **Purpose**: Detects buffer handling vulnerabilities in C/C++/Go code including use-after-free and integer overflow
- **CWE Coverage**:
  - **CWE-120** Buffer Overflow: `strcpy`, `strcat`, `sprintf`, `gets`, `wcscpy`, `wcscat`
  - **CWE-787** Out-of-Bounds Write: `memcpy`/`memmove` without `sizeof` validation
  - **CWE-125** Out-of-Bounds Read: Array access without bounds checking (excludes constant indices)
  - **CWE-416** Use After Free: `free()` followed by pointer dereference within 5 lines
  - **CWE-190** Integer Overflow: Unchecked integer arithmetic, `malloc(count * size)` without overflow guard
- **Severity**: critical (CWE-120, CWE-416), high (CWE-787, CWE-190), medium (CWE-125)
- **Detection**: Regex patterns on C/C++/Go files only; excludes bounded alternatives and overflow checks

## auth_check

- **Function**: `check_authentication(source_path: str) -> dict`
- **Purpose**: Detects authentication weaknesses including hardcoded secrets and missing auth
- **CWE Coverage**:
  - **CWE-798** Hardcoded Credentials: passwords, API keys, tokens, secrets in string literals
  - **CWE-287** Improper Authentication: MD5/SHA1 password hashing, direct password comparison
  - **CWE-306** Missing Authentication: Route handlers without auth decorators/middleware
  - **CWE-521** Weak Password Requirements: Minimum length under 6 characters
- **Severity**: critical (CWE-798), high (CWE-287, CWE-306), medium (CWE-521)
- **Detection**: Pattern matching with safe-value exclusions (env vars, placeholders, test values)

## crypto_check

- **Function**: `check_cryptography(source_path: str) -> dict`
- **Purpose**: Detects cryptographic weaknesses across algorithms, key sizes, randomness, and hashing
- **CWE Coverage**:
  - **CWE-327** Broken Cryptographic Algorithm: DES, RC4, Blowfish, 3DES, ECB mode
  - **CWE-326** Inadequate Encryption Strength: RSA keys under 2048 bits
  - **CWE-330** Insufficient Randomness: `random.random()`, `Math.random()`, `rand()`
  - **CWE-328** Reversible One-Way Hash: MD5/SHA1 for integrity (excludes checksum/cache/HMAC)
- **Severity**: critical (CWE-327, hardcoded keys), high (CWE-326, CWE-330), medium (CWE-328)
- **Detection**: Pattern matching with context-aware exclusions

## input_validation_check

- **Function**: `check_input_validation(source_path: str) -> dict`
- **Purpose**: Detects input validation failures including path traversal, XXE, CSRF, and deserialization
- **CWE Coverage**:
  - **CWE-22** Path Traversal: `os.path.join` with user input, `../` patterns
  - **CWE-20** Improper Input Validation: Direct request data access without validation
  - **CWE-434** Unrestricted File Upload: File upload without type/size validation
  - **CWE-611** XML External Entity (XXE): XML parsing without entity restriction
  - **CWE-352** Cross-Site Request Forgery (CSRF): POST/PUT/DELETE without CSRF token
  - **CWE-502** Deserialization of Untrusted Data: `pickle.loads`, unsafe `yaml.load`
- **Severity**: critical (CWE-502), high (CWE-22, CWE-352, CWE-434, CWE-611), medium (CWE-20)
- **Detection**: Context window scanning with safe-alternative exclusions

## resource_check

- **Function**: `check_resource_management(source_path: str) -> dict`
- **Purpose**: Detects resource management issues including leaks, null dereferences, and unbounded allocations
- **CWE Coverage**:
  - **CWE-400** Uncontrolled Resource Consumption: Infinite loops
  - **CWE-404** Improper Resource Shutdown: Open without close/defer/with
  - **CWE-476** NULL Pointer Dereference: No nil check after call
  - **CWE-770** Allocation Without Limits: Unbounded appends/makes
- **Severity**: high (CWE-400, CWE-404, CWE-476), medium (CWE-770)

## info_exposure_check

- **Function**: `check_information_exposure(source_path: str) -> dict`
- **Purpose**: Detects information disclosure through error messages, logs, cleartext storage
- **CWE Coverage**:
  - **CWE-209** Error Message Disclosure: Stack traces in responses
  - **CWE-532** Sensitive Data in Logs: Passwords/tokens in log output
  - **CWE-312** Cleartext Storage: Sensitive values in plaintext
  - **CWE-200** Sensitive Info Exposure: Internal details in responses
- **Severity**: critical (CWE-532, CWE-312), high (CWE-209, CWE-200)

## access_control_check

- **Function**: `check_access_control(source_path: str) -> dict`
- **Purpose**: Detects authorization and access control vulnerabilities
- **CWE Coverage**:
  - **CWE-862** Missing Authorization: Routes without auth middleware
  - **CWE-863** Incorrect Authorization: Role via string comparison
  - **CWE-639** Authorization Bypass Through User-Controlled Key (IDOR): User-supplied IDs without ownership check
  - **CWE-269** Improper Privilege: chmod 777, setuid(0), running as root
- **Severity**: critical (CWE-269), high (CWE-862, CWE-863, CWE-639)

## error_handling_check

- **Function**: `check_error_handling(source_path: str) -> dict`
- **Purpose**: Detects error handling weaknesses
- **CWE Coverage**:
  - **CWE-252** Unchecked Return Value: Go `_, _ = func()` patterns
  - **CWE-755** Improper Exception Handling: Bare `except:`, `catch(...)`
  - **CWE-390** Error Without Action: Empty catch/except blocks
  - **CWE-754** Unchecked I/O: I/O without error handling
- **Severity**: high (CWE-252, CWE-755, CWE-390), medium (CWE-754)

## concurrency_check

- **Function**: `check_concurrency(source_path: str) -> dict`
- **Purpose**: Detects concurrency vulnerabilities
- **CWE Coverage**:
  - **CWE-367** TOCTOU: File check followed by file use
  - **CWE-662** Improper Synchronization: Threading without locks
  - **CWE-833** Deadlock: Nested lock acquisition
- **Severity**: high (CWE-367, CWE-662, CWE-833)

## web_security_check

- **Function**: `check_web_security(source_path: str) -> dict`
- **Purpose**: Detects web-specific security vulnerabilities including redirects, cookies, and session handling
- **CWE Coverage**:
  - **CWE-601** Open Redirect: User-controlled redirect targets without URL validation
  - **CWE-1004** Cookie Without HttpOnly: Cookies set without HttpOnly flag
  - **CWE-384** Session Fixation: Session populated from user input without regeneration
  - **CWE-614** Cookie Without Secure: Cookies missing Secure flag for HTTPS
  - **CWE-113** CRLF Injection: User input in HTTP headers without CR/LF stripping
- **Severity**: high (CWE-601, CWE-384, CWE-113), medium (CWE-1004, CWE-614)
- **Detection**: Context-aware scanning with safe-pattern exclusions (URL validation, HttpOnly/Secure flags, session regeneration)

## configuration_check

- **Function**: `check_configuration(source_path: str) -> dict`
- **Purpose**: Detects configuration and deployment security issues
- **CWE Coverage**:
  - **CWE-1188** Insecure Default Initialization: DEBUG=True, CORS allow all, verify=False
  - **CWE-668** Service Bound to All Interfaces: Binding 0.0.0.0 without restriction
  - **CWE-326** Weak TLS/SSL Protocol: TLS 1.0, SSLv3, weak protocol versions
  - **CWE-295** Certificate Verification Disabled: InsecureSkipVerify, verify=False
  - **CWE-319** Weak HSTS Configuration: Short max-age values
  - **CWE-732** Incorrect Permissions: chmod 777, umask(0), world-writable files
  - **CWE-668** Resource Exposure: Internal ports exposed publicly (3306, 5432, 6379)
  - **CWE-1295** Debug in Production: Debug mode enabled outside dev/test context
- **Severity**: high (CWE-732, CWE-668, CWE-1295), medium (CWE-1188, CWE-326, CWE-295, CWE-319)
- **Detection**: Scans code and config files (.py, .go, .yml, .toml, .ini, .env, etc.); excludes test/dev files

## dependency_check

- **Function**: `check_dependency_security(source_path: str) -> dict`
- **Purpose**: Detects supply chain and dependency security issues
- **CWE Coverage**:
  - **CWE-1104** Unmaintained Components: Unpinned dependency versions in requirements.txt
  - **CWE-829** Untrusted Source: Scripts loaded over HTTP, pipe-to-shell installs
  - **CWE-494** Download Without Integrity: Code downloaded without checksum verification
  - **CWE-506** Embedded Malicious Code: Base64-decode-then-exec patterns, obfuscated execution
- **Severity**: critical (CWE-506), high (CWE-829, CWE-494), medium (CWE-1104)
- **Detection**: Scans dependency manifests (requirements.txt, package.json, go.mod) and code files; SRI/checksum context exclusions

## data_handling_check

- **Function**: `check_data_handling(source_path: str) -> dict`
- **Purpose**: Detects data handling and type safety vulnerabilities
- **CWE Coverage**:
  - **CWE-134** Format String: User input as format string argument in printf/sprintf/logging
  - **CWE-681** Incorrect Numeric Conversion: Narrowing casts without overflow checks
  - **CWE-704** Unsafe Type Cast: `reinterpret_cast`, `unsafe.Pointer`, TypeScript `as any`
  - **CWE-838** Inappropriate Encoding: ASCII/Latin-1 with errors='ignore', encoding mismatches
  - **CWE-1321** Prototype Pollution: Object.assign/merge/spread from user input without validation
- **Severity**: high (CWE-134, CWE-704, CWE-1321), medium (CWE-681, CWE-838)
- **Detection**: Pattern matching with safe-alternative exclusions (schema validators, Object.create(null), UTF-8)

## memory_safety_check

- **Function**: `check_memory_safety(source_path: str) -> dict`
- **Purpose**: Detects memory lifecycle and initialization bugs in C/C++/Go/Rust
- **CWE Coverage**:
  - **CWE-401** Memory Leak: malloc/calloc/new without matching free/delete in file
  - **CWE-415** Double Free: Same pointer freed twice within 10 lines
  - **CWE-457** Uninitialized Variable: Variable declared without initialization before use
  - **CWE-824** Uninitialized Pointer: Pointer dereferenced before initialization
  - **CWE-562** Return Stack Address: Returning address of local variable
  - **CWE-467** sizeof on Pointer: `sizeof(ptr)` instead of `sizeof(*ptr)`
- **Severity**: critical (CWE-415, CWE-824, CWE-562), high (CWE-401), medium (CWE-457, CWE-467)
- **Detection**: Scans C/C++/Go/Rust files only; window-based analysis for use-after-alloc and double-free patterns

## path_equivalence_check

- **Function**: `check_path_equivalence(source_path: str) -> dict`
- **Family**: Path-equivalence weaknesses — children of CWE-41 (Improper Resolution of Path Equivalence). These are string-equivalence tricks on filenames that bypass allowlists, path comparisons, or access controls.
- **CWE Coverage**:
  - **CWE-42** Trailing Dot ('filedir.'): `foo.txt.`
  - **CWE-43** Multiple Trailing Dots ('filedir...'): `foo.txt....`
  - **CWE-46** Trailing Whitespace ('filedir '): `foo.txt ` (space/tab at end)
  - **CWE-48** Internal Whitespace ('file(SPACE)name'): `foo bar.txt`
  - **CWE-49** Trailing Slash ('filedir/'): `foo.txt/`
  - **CWE-50** Multiple Leading Slashes ('//absolute/path'): `//etc/passwd`
  - **CWE-51** Multiple Internal Slashes ('/absolute//path'): `/etc//passwd`
  - **CWE-52** Multiple Trailing Slashes ('filedir//'): `/etc/passwd//`
  - **CWE-54** Trailing Backslash ('filedir\\'): `foo\\`
  - **CWE-55** Path Equivalence Using Single Dot ('/./'): `/./foo`
  - **CWE-56** Path Equivalence: 'filedir*' (Wildcard): `foo*.txt`
  - **CWE-57** Path Equivalence: 'fakedir/../realdir/filename': `fake/../real/f`
- **Detection Approach** — two-stage filtering to suppress false positives:
  1. **Path-call gate**: The line must invoke a recognized filesystem API (Python `open`/`os.path.*`/`pathlib.Path`, Go `ioutil.ReadFile`, Java `Files.read`/`Paths.get`, JavaScript `fs.readFile`, C `fopen`/`unlink`/`stat`, etc.). Lines without such a call are skipped — this filters out log messages, regex patterns, version strings, URLs inside `requests.get`, etc.
  2. **Path-shape filter**: The quoted literal content must contain at least one path signal (`/`, `\`, `../`, an extension tail like `.py`/`.json`, or a trailing dot). Plain identifiers like `"Hello world"` inside a path call are excluded.
  3. **Variant regexes**: Each of the 12 variants is a compiled pattern with absolute anchors `\A` / `\Z` operating on the literal content only. One variant per literal (first match wins, ordered by specificity).
- **Severity** (calibrated to false-positive risk):
  - **high**: CWE-57 (directory-traversal equivalence — high-signal, classical `../` bypass)
  - **medium**: CWE-43, CWE-54, CWE-52, CWE-50, CWE-51, CWE-55 (specific path shapes, low FP)
  - **low**: CWE-42, CWE-46, CWE-48, CWE-49, CWE-56 (noisier variants — trailing dot, whitespace, wildcard)
- **FP Risk Note**: Wildcards (CWE-56) can still fire on glob-style path literals passed to `open(glob_result)` — this is by-design (catalog variant) but requires manual review. Internal-whitespace (CWE-48) assumes filenames with embedded spaces are unusual; this may produce FPs on legitimate filenames with spaces.
- **Language-agnostic**: Scans all source extensions; skips test and generated files.

## catalog_detector

- **Function**: `check_catalog_generic(source_path: str) -> dict`
- **Purpose**: Catalog-driven generic CWE detection engine covering 400+ additional CWE IDs beyond the 16 dedicated skills using enriched CWE v4.19.1 metadata
- **Mechanism**:
  - Loads all CWEs with static-detectability score >= 0.3 from enriched catalog
  - Builds keyword-to-CWE inverted index for fast file-level matching
  - For each code line, extracts keywords and scores against CWE keyword sets
  - Requires at least 2 keyword matches to reduce false positives
  - Filters by language applicability (e.g., C-only CWEs skip Python files)
  - Context-aware safe exclusions (sanitize, validate, escape, etc.) raise threshold
  - Severity derived from CWE catalog consequences (impact → severity mapping)
  - Skips Pillar/Class abstractions (too generic) and all 67 dedicated-skill CWEs (avoid duplication)
  - Limits to 15 findings per file to avoid noise
- **CWE Coverage**: ~400+ CWE IDs not covered by dedicated skills, including:
  - Uncommon injection variants, race conditions, API misuse
  - Platform-specific weaknesses, deprecated function usage
  - Framework-specific patterns, configuration weaknesses
- **Severity**: Derived from CWE catalog consequence impact data (critical/high/medium/low)
- **Detection**: Keyword-based matching with catalog confidence scoring; findings enriched with catalog metadata (name, likelihood, mitigations)
- **Catalog Confidence**: Each finding carries a `catalog_confidence` score = `static_detectability × keyword_match_score`

## Self-Learning (LLM Phase)

When the LLM phase is enabled (`VULTURE_USE_LLM=true`), the agent augments skill findings with:
- **Catalog context injection**: Top 80 static-detectable CWEs injected as structured LLM context
- **Self-learning protocol**: Prior findings with prove_status drive confidence adjustment
  - BOOST: Patterns similar to previously verified findings get higher confidence
  - DEMOTE: Patterns similar to previously not-reproduced findings get lower confidence
  - SKIP: Known issues from memory are excluded to avoid redundancy
- **MMR-based memory retrieval**: Maximal Marginal Relevance balances relevance vs diversity
  - Embedding cosine similarity when vectors available, Jaccard title-token fallback
  - Prove agent feedback loop: verified=1.3× boost, not_reproduced=0.6× demotion
  - Staleness decay for older findings
