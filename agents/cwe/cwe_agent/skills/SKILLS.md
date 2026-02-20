# CWE Weakness Auditor - Skills

Analyzes source code for Common Weakness Enumeration (CWE v4.19.1) vulnerabilities across 10 categories covering 40 CWE IDs.

## injection_check

- **Function**: `check_injection(source_path: str) -> dict`
- **Purpose**: Detects code injection vulnerabilities across SQL, OS command, XSS, and dynamic code execution
- **CWE Coverage**:
  - **CWE-89** SQL Injection: f-string/format SQL queries, Sprintf-based queries
  - **CWE-78** OS Command Injection: `os.system()`, `os.popen()`, `subprocess` with `shell=True`
  - **CWE-79** Cross-Site Scripting: `innerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`
  - **CWE-94** Code Injection: `eval()`, `exec()`, `new Function()`, string-based `setTimeout`/`setInterval`
- **Severity**: critical (CWE-89, CWE-78, CWE-94), high (CWE-79)
- **Detection**: Regex pattern matching with safe-call exclusions (static string arguments, import lines)

## buffer_check

- **Function**: `check_buffer_handling(source_path: str) -> dict`
- **Purpose**: Detects buffer handling vulnerabilities in C/C++/Go code
- **CWE Coverage**:
  - **CWE-120** Buffer Overflow: `strcpy`, `strcat`, `sprintf`, `gets`, `wcscpy`, `wcscat`
  - **CWE-787** Out-of-Bounds Write: `memcpy`/`memmove` without `sizeof` validation
  - **CWE-125** Out-of-Bounds Read: Array access without bounds checking (excludes constant indices)
- **Severity**: critical (CWE-120), high (CWE-787), medium (CWE-125)
- **Detection**: Regex patterns on C/C++/Go files only (`.c`, `.h`, `.cpp`, `.cc`, `.cxx`, `.hpp`, `.go`); excludes bounded alternatives (`strncpy`, `snprintf`, `fgets`)

## auth_check

- **Function**: `check_authentication(source_path: str) -> dict`
- **Purpose**: Detects authentication weaknesses including hardcoded secrets and missing auth
- **CWE Coverage**:
  - **CWE-798** Hardcoded Credentials: passwords, API keys, tokens, secrets in string literals
  - **CWE-287** Improper Authentication: MD5/SHA1 password hashing, direct password comparison
  - **CWE-306** Missing Authentication: Route handlers without auth decorators/middleware
  - **CWE-521** Weak Password Requirements: Minimum length under 6 characters
- **Severity**: critical (CWE-798), high (CWE-287, CWE-306), medium (CWE-521)
- **Detection**: Pattern matching with safe-value exclusions (env vars, placeholders, test values); context-aware auth decorator scanning

## crypto_check

- **Function**: `check_cryptography(source_path: str) -> dict`
- **Purpose**: Detects cryptographic weaknesses across algorithms, key sizes, randomness, and hashing
- **CWE Coverage**:
  - **CWE-327** Broken Cryptographic Algorithm: DES, RC4, Blowfish, 3DES, ECB mode
  - **CWE-326** Inadequate Encryption Strength: RSA keys under 2048 bits (512, 768, 1024)
  - **CWE-330** Insufficient Randomness: `random.random()`, `Math.random()`, `rand()`, `java.util.Random`
  - **CWE-328** Reversible One-Way Hash: MD5/SHA1 for integrity (excludes checksum/cache/HMAC contexts)
- **Severity**: critical (CWE-327, hardcoded keys), high (CWE-326, CWE-330), medium (CWE-328)
- **Detection**: Pattern matching with context-aware exclusions (deprecated/legacy comments, secure alternatives like `secrets`/`crypto/rand`)

## input_validation_check

- **Function**: `check_input_validation(source_path: str) -> dict`
- **Purpose**: Detects input validation failures including path traversal, XXE, and file upload issues
- **CWE Coverage**:
  - **CWE-22** Path Traversal: `os.path.join` with user input, `../` patterns, `open()` with request data
  - **CWE-20** Improper Input Validation: Direct `request.args`/`params`/`form` access without validation
  - **CWE-434** Unrestricted File Upload: File upload handling without type/size validation
  - **CWE-611** XML External Entity (XXE): XML parsing without entity restriction
- **Severity**: high (CWE-22, CWE-434, CWE-611), medium (CWE-20)
- **Detection**: Pattern matching with context window scanning (checks surrounding lines for validation/sanitization); excludes safe alternatives (`defusedxml`, `secure_filename`, `pydantic`)

## resource_check

- **Function**: `check_resource_management(source_path: str) -> dict`
- **Purpose**: Detects resource management issues including leaks and unbounded consumption
- **CWE Coverage**:
  - **CWE-400** Uncontrolled Resource Consumption: Infinite loops (`while True`, `for {`)
  - **CWE-404** Improper Resource Shutdown: `open()`/`os.Open()`/`sql.Open()` without close/defer/with
- **Severity**: high (CWE-400, CWE-404)
- **Detection**: Pattern matching with context-aware cleanup detection (scans next 5 lines for `defer`, `.close()`, `with` statement)

## info_exposure_check

- **Function**: `check_information_exposure(source_path: str) -> dict`
- **Purpose**: Detects information disclosure through error messages, logs, and cleartext storage
- **CWE Coverage**:
  - **CWE-209** Error Message Information Disclosure: `traceback.print_exc()`, `.printStackTrace()`, stack trace returns
  - **CWE-532** Sensitive Data in Logs: Logging of passwords, tokens, secrets, API keys
  - **CWE-312** Cleartext Storage: Sensitive values stored in plaintext string literals
- **Severity**: critical (CWE-532, CWE-312), high (CWE-209)
- **Detection**: Pattern matching with safe-storage exclusions (hashing, env vars, encryption contexts)

## access_control_check

- **Function**: `check_access_control(source_path: str) -> dict`
- **Purpose**: Detects authorization and access control vulnerabilities
- **CWE Coverage**:
  - **CWE-862** Missing Authorization: Route handlers without any auth middleware (Flask, Express, Spring, Go)
  - **CWE-863** Incorrect Authorization: Role checks via direct string comparison (`role == "admin"`)
  - **CWE-284** Improper Access Control (IDOR): User-supplied IDs used without ownership verification
  - **CWE-269** Improper Privilege Management: `chmod 777`, `setuid(0)`, running as root
- **Severity**: critical (CWE-269), high (CWE-862, CWE-863, CWE-284)
- **Detection**: File-level context scanning (checks if any auth middleware exists in the file before flagging routes); ownership check detection for IDOR

## error_handling_check

- **Function**: `check_error_handling(source_path: str) -> dict`
- **Purpose**: Detects error handling weaknesses including swallowed exceptions and unchecked returns
- **CWE Coverage**:
  - **CWE-252** Unchecked Return Value: Go patterns like `_, _ = func()` or `_ = obj.Method()`
  - **CWE-755** Improper Exception Handling: Bare `except:`, `catch(...)`, `catch(Exception e)`
  - **CWE-390** Error Detection Without Action: Empty catch/except blocks (`except SomeError: pass`)
- **Severity**: high (CWE-252, CWE-755, CWE-390)
- **Detection**: Pattern matching with next-line inspection for empty handlers (checks if `pass` follows except)

## concurrency_check

- **Function**: `check_concurrency(source_path: str) -> dict`
- **Purpose**: Detects concurrency vulnerabilities including race conditions and deadlocks
- **CWE Coverage**:
  - **CWE-367** Time-of-Check Time-of-Use (TOCTOU): `os.path.exists()` followed by `open()` within 5 lines
  - **CWE-662** Improper Synchronization: `threading.Thread()` or `go func()` without any locks in the file
- **Severity**: high (CWE-367, CWE-662)
- **Detection**: Two-phase check: identifies check operations, then scans a 5-line window for use operations; file-level lock detection for synchronization assessment
