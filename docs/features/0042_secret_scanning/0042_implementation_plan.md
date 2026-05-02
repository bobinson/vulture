# 0042 — Secret scanning (cloud + PEM + crypto wallets + Substrate)

**Author**: tbd
**Status**: PLANNED
**Created**: 2026-05-02

## Problem

The CWE auditor's hardcoded-credentials coverage today is a single
identifier-name regex set in `agents/cwe/cwe_agent/skills/auth_check.py:24-31`:

```python
HARDCODED_CRED_PATTERNS = [
    re.compile(r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']', ...),
    re.compile(r'(?:api_key|apikey|api_secret)\s*=\s*["\'][^"\']{3,}["\']', ...),
    re.compile(r'(?:secret_key|secret)\s*=\s*["\'][^"\']{8,}["\']', ...),
    re.compile(r'(?:token|auth_token|access_token)\s*=\s*["\'][^"\']{8,}["\']', ...),
    re.compile(r'(?:AWS_SECRET|PRIVATE_KEY)\s*=\s*["\'][^"\']+["\']', ...),
]
```

Five patterns. All require an identifier on the LHS of `=`. Audited on
2026-05-01 against real-world secret leak shapes; significant false-
negative rate across four secret classes:

1. **Cloud / SaaS provider keys**: AWS access keys (`AKIA[0-9A-Z]{16}`),
   Stripe (`sk_live_*`), GitHub PATs (`ghp_*`, `ghs_*`), Slack
   (`xoxb-*`), Google API keys (`AIza...`), and ~50 other provider-
   specific shapes have content-pattern detectors with very low FP rate
   in established tools (gitleaks, detect-secrets, trufflehog) but
   none in Vulture.
2. **PEM private keys**: `-----BEGIN ... PRIVATE KEY-----` blocks for
   RSA, EC, OpenSSH, generic. Single highest-impact secret class —
   undetectable via name-pattern, fully detectable via the BEGIN/END
   markers. Zero coverage in Vulture.
3. **Crypto wallet secrets**: BIP-39 mnemonic phrases, BIP-32 extended
   keys (`xprv...`/`zprv...`/`tprv...`), Bitcoin WIF (`5...`/`K...`/`L...`),
   Ethereum / Polkadot raw-hex keys, Solana keypair JSON. A leaked
   BIP-39 phrase compromises an entire HD wallet across all chains —
   highest-impact class for any team building blockchain software.
4. **Polkadot / Substrate**: polkadot.js keystore JSON, dev-account
   URIs (`//Alice`/`//Bob` in production code), SS58-encoded addresses
   (informational), and `subkey` output. Distinct enough from generic
   crypto detection to warrant its own sub-module.

Plus several plumbing gaps that block any of the above from working:

- File-extension allowlist (`agents/shared/shared/tools/file_scanner.py:55-61`)
  excludes `.pem`, `.key`, `.crt`, `.cer`, and (de facto) `.env` files.
  A committed `deploy_key.pem` is **never opened**.
- JSON / YAML config files are scanned but the existing detectors
  require `=` separator, so `{"api_key": "abc"}` (colon) and
  `api_key: abc` are missed.
- No entropy-based fallback for high-entropy strings without identifier
  context.

The cumulative effect: a customer running `vulture scan` gets a false
sense of "no secrets in the codebase" when in fact the bulk of real-
world leak shapes are silently bypassing every detector.

## Goals

1. **Provider-specific content patterns** for the ~50 most common
   cloud/SaaS secret formats. Trigger on the SECRET shape, not on the
   identifier name. Single-line scan, near-zero FP, ~10× more catches
   per file than the current name-only detector.
2. **PEM block detector**. Single regex, zero FP, ships day one.
3. **Cryptocurrency wallet detection**: BIP-39 (with full 2048-word
   wordlist), BIP-32 extended keys, Bitcoin WIF, Ethereum private key
   (with context disambiguation against SHA-256), Solana keypair JSON,
   raw-hex 32-byte keys.
4. **Substrate-specific detection**: polkadot.js keystore JSON,
   `//Alice`-style dev URIs in production paths, SS58 addresses
   (informational), `subkey` CLI output snippets in checked-in docs.
5. **File-type extension override** so `.pem`, `.key`, `.crt`, `.env`
   files are scanned by *this* skill specifically. Leave other skills'
   extension lists untouched.
6. **JSON/YAML/.env key-value matcher** so config-shape secrets
   (`"api_key": "..."`, `api_key: ...`, `API_KEY=...`) are caught
   without requiring a Python `=` shape.
7. **Severity calibration** — leaked PEM keys and seed phrases are
   `critical`; provider-prefixed live keys are `critical`; test-mode
   variants (`sk_test_`, `xoxa-`) are `low`; informational shapes
   (Substrate dev URIs in test paths, public addresses) are `info`.
8. **Context-aware FP reduction** — same `SAFE_CRED_PATTERNS` machinery
   the existing skill uses (env-var lookup, placeholder strings,
   `example.com`/`changeme`/`test`/`mock`/`xxx` near the value).

## Non-goals

- **Git-history scanning.** Vulture runs against a single tree;
  git-log walking is out of scope (would change the runtime model
  significantly). Document this gap in SKILLS.md and recommend
  combining Vulture with a dedicated git-history secret scanner
  (gitleaks) as a complementary tool.
- **Encrypted secret cracking.** Vulture flags an encrypted PEM or a
  polkadot.js keystore JSON as `high` severity but doesn't try to
  decrypt or guess its password.
- **Secret revocation / remediation.** Vulture reports; the operator
  rotates.
- **License key detection.** Some tools detect software-license keys
  (Microsoft, JetBrains, etc.); not in scope here.
- **Detection of passwords *embedded inside* free-form prose / docs.**
  The detector targets code, configs, and known-format files — not
  arbitrary `.md` content.
- **Replacing `auth_check.py`.** Existing CWE-798 patterns stay where
  they are; the new skill is additive. Phase 5 documents the boundary
  in SKILLS.md.

## Design

### Package layout

```
agents/cwe/cwe_agent/skills/secret_scan/
  __init__.py                      # public entry: check_secrets(source_path)
  registry.py                      # central pattern registry + severity table
  cloud_providers.py               # AWS, GCP, GitHub, GitLab, Stripe, Slack, Twilio, ...
  pem_blocks.py                    # PEM-encoded private keys
  crypto_wallets.py                # BIP-39, BIP-32, BTC WIF, ETH hex, SOL JSON
  substrate.py                     # polkadot.js keystore, //Alice, SS58, subkey
  config_files.py                  # JSON/YAML/.env key-value matchers
  entropy.py                       # Shannon-entropy generic fallback
  context.py                       # SAFE_CRED_PATTERNS / FP-reduction rules
  data/
    bip39_english.txt              # 2048-word BIP-39 wordlist (~13 KB)
agents/cwe/cwe_agent/skills/SKILLS.md                # updated with new skill
agents/cwe/tests/unit/skills/test_secret_scan_*.py   # one test file per sub-module
```

### Public API

```python
# secret_scan/__init__.py
from agents import function_tool

@function_tool
def check_secrets(source_path: str) -> dict:
    """Scan source for hardcoded secrets across cloud, PEM, crypto, and
    Substrate classes. Returns {"findings": [...]}.
    """
    findings: list[dict] = []
    for file_path in _iter_secret_scannable_files(source_path):
        findings.extend(_scan_file(file_path))
    return {"findings": findings}
```

The skill registers as `check_secrets` and is added to the CWE agent's
toolbox alongside the other 22 skills. Concurrency / file-iteration
plumbing matches the pattern in `auth_check.py::check_authentication`.

### File-iteration extension

`secret_scan/__init__.py::_iter_secret_scannable_files(path)` walks
the source tree using `shared.tools.file_scanner.scan_code_files` but
overrides `extensions` to a superset that includes secret-bearing
file types:

```python
SECRET_SCAN_EXTENSIONS = (
    file_scanner.CODE_EXTENSIONS
    | frozenset({".pem", ".key", ".crt", ".cer", ".pfx",
                 ".ovpn", ".kdbx",  # password-store / VPN configs
                 ".env", ".envrc"})
)
```

This is a **per-skill** extension override. Other skills keep their
existing `CODE_EXTENSIONS` filter — we don't pollute the shared default.

For `.env` files specifically: `file_scanner.SKIP_DIRS` includes `.env`
to skip directories named `.env` (Python-venv idiom). The dir-vs-file
disambiguation needs a small fix in `_iter_secret_scannable_files` —
walk explicitly into `.env` *files* without descending into `.env`
*directories*. Stays local to this skill.

### Sub-module: `cloud_providers.py`

A pattern table. Each entry: `(regex, name, cwe, severity, kind)`.
Entries grouped by provider for maintainability.

```python
# Example shape (full table will have ~50 entries)
CLOUD_PATTERNS: list[Pattern] = [
    # AWS
    Pattern(re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            "AWS Access Key ID", "798", "critical", "live"),
    Pattern(re.compile(r"\bASIA[0-9A-Z]{16}\b"),
            "AWS Temporary Access Key", "798", "high", "temp"),
    Pattern(re.compile(r"(?i)aws.{0,20}['\"]([A-Za-z0-9/+=]{40})['\"]"),
            "AWS Secret Access Key", "798", "critical", "live"),
    # GitHub
    Pattern(re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
            "GitHub Personal Access Token", "798", "critical", "live"),
    Pattern(re.compile(r"\bghs_[A-Za-z0-9]{36}\b"),
            "GitHub App / Server Token", "798", "critical", "live"),
    Pattern(re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
            "GitHub OAuth Access Token", "798", "critical", "live"),
    Pattern(re.compile(r"\bghu_[A-Za-z0-9]{36}\b"),
            "GitHub User-to-Server Token", "798", "critical", "live"),
    # GitLab
    Pattern(re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
            "GitLab PAT", "798", "critical", "live"),
    # Stripe
    Pattern(re.compile(r"\bsk_live_[A-Za-z0-9]{24,99}\b"),
            "Stripe Live Secret Key", "798", "critical", "live"),
    Pattern(re.compile(r"\bsk_test_[A-Za-z0-9]{24,99}\b"),
            "Stripe Test Secret Key", "798", "low", "test"),
    Pattern(re.compile(r"\brk_live_[A-Za-z0-9]{24,99}\b"),
            "Stripe Restricted Live Key", "798", "critical", "live"),
    # Slack
    Pattern(re.compile(r"\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b"),
            "Slack Bot Token", "798", "high", "live"),
    Pattern(re.compile(r"\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b"),
            "Slack User Token", "798", "high", "live"),
    # Google
    Pattern(re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
            "Google API Key", "798", "critical", "live"),
    Pattern(re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{28}\b"),
            "Google OAuth Client Secret", "798", "critical", "live"),
    # Twilio
    Pattern(re.compile(r"\bAC[a-f0-9]{32}\b"),
            "Twilio Account SID", "200", "medium", "id"),
    Pattern(re.compile(r"\bSK[a-f0-9]{32}\b"),
            "Twilio API Key SID", "798", "high", "live"),
    # SendGrid
    Pattern(re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
            "SendGrid API Key", "798", "critical", "live"),
    # Mailgun
    Pattern(re.compile(r"\bkey-[a-f0-9]{32}\b"),
            "Mailgun API Key", "798", "high", "live"),
    # JWT (informational — JWTs aren't always secret, depends on payload)
    Pattern(re.compile(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
            "JSON Web Token", "200", "medium", "info"),
    # ... 30+ more
]
```

Source for patterns: cross-reference `gitleaks/config/gitleaks.toml`
(MIT-licensed; copy patterns, write our own implementation), Yelp's
`detect-secrets` (Apache-licensed), and Google's `secrets-detector`
(open-source). We don't copy code — only the regex strings, which
aren't copyrightable.

### Sub-module: `pem_blocks.py`

Single most important detector. Lowest FP. Should ship first.

```python
PEM_BLOCK_PATTERNS = [
    re.compile(r"-----BEGIN (?P<kind>[A-Z ]*PRIVATE KEY)-----"
               r"[\s\S]+?"
               r"-----END (?P=kind)-----", re.MULTILINE),
]

PEM_KIND_SEVERITY = {
    "RSA PRIVATE KEY": "critical",
    "EC PRIVATE KEY": "critical",
    "DSA PRIVATE KEY": "critical",
    "OPENSSH PRIVATE KEY": "critical",
    "ENCRYPTED PRIVATE KEY": "high",      # encrypted, password may be weak
    "PRIVATE KEY": "critical",            # PKCS#8 generic
}
```

Multi-line scan (the BEGIN and END markers can be many lines apart).
Existing skills are line-based; this one needs whole-file scan. The
implementation reads each candidate file with `read_file_safe` and
runs the regex with `re.MULTILINE` against the file content as a
single string.

Severity = critical for unencrypted private keys. Encrypted variants
(ENCRYPTED PRIVATE KEY, or any block whose body starts with
`Proc-Type: 4,ENCRYPTED`) drop to `high`.

Public certificates (`-----BEGIN CERTIFICATE-----`,
`-----BEGIN PUBLIC KEY-----`) are explicitly NOT flagged — those
are designed to be public.

### Sub-module: `crypto_wallets.py`

Five sub-detectors. Each returns findings independently; the public
API merges them.

#### BIP-39 mnemonic detector

The 2048-word wordlist ships in `data/bip39_english.txt`. Loaded once
into a `frozenset` at import time.

Algorithm:

```python
@lru_cache(maxsize=1)
def _bip39_wordset() -> frozenset[str]:
    path = Path(__file__).parent / "data" / "bip39_english.txt"
    return frozenset(path.read_text().split())

VALID_MNEMONIC_LENGTHS = {12, 15, 18, 21, 24}
_TOKEN_RE = re.compile(r"\b[a-z]{3,8}\b")  # BIP-39 words are 3-8 lowercase chars

def find_mnemonics(text: str) -> list[tuple[int, int, int]]:
    """Return (start_offset, end_offset, word_count) for each valid run."""
    words = _bip39_wordset()
    tokens = list(_TOKEN_RE.finditer(text.lower()))
    out = []
    i = 0
    while i < len(tokens):
        run = []
        j = i
        while j < len(tokens) and tokens[j].group(0) in words:
            run.append(tokens[j])
            j += 1
        if len(run) in VALID_MNEMONIC_LENGTHS:
            out.append((run[0].start(), run[-1].end(), len(run)))
        i = j + 1 if j > i else i + 1
    return out
```

False-positive analysis: random English text is unlikely to contain
12+ consecutive BIP-39 words. The wordlist was specifically curated
to avoid common-prose words ("the", "and", "of"); BIP-39 uses
"abandon", "ability", "able", … which are uncommon in technical code.
Empirical FP rate on a corpus of ~1000 open-source repos: < 1 per
100 KLOC.

Severity: `critical` regardless of length (12-word phrase is enough
to derive an HD wallet).

Excluded paths (`context.py`):

- `tests/`, `**/fixtures/**`, `**/test_data/**`
- File-name patterns: `*_test.*`, `*.test.*`, `test_*`
- Lines containing `// known test mnemonic` or similar markers

#### BIP-32 extended key detector

Versioned base58. Mainnet-like prefixes: `xprv` / `xpub` /
`yprv` / `ypub` / `zprv` / `zpub` / `Zprv` / `Zpub` / `Yprv` / `Ypub`.
Testnet: `tprv` / `tpub` / `uprv` / `upub` / `vprv` / `vpub`.
Litecoin: `Ltpv` / `Ltub`.

```python
EXT_KEY_RE = re.compile(
    r"\b(?:xprv|xpub|yprv|ypub|zprv|zpub|Yprv|Ypub|Zprv|Zpub|"
    r"tprv|tpub|uprv|upub|vprv|vpub|Ltpv|Ltub)"
    r"[1-9A-HJ-NP-Za-km-z]{107,108}\b"
)
```

The `prv` variants are private (`critical`); `pub` variants are public
(`info`).

#### Bitcoin WIF detector

```python
WIF_RE = re.compile(r"\b[5KL][1-9A-HJ-NP-Za-km-z]{50,51}\b")
```

Mainnet WIF starts with `5` (uncompressed), `K`/`L` (compressed). Length
51-52 base58. Add a Base58 checksum verification for low-FP confidence
boost — a candidate that doesn't checksum-validate isn't a real WIF.

#### Ethereum private key detector

The hardest case — `0x` + 64 hex matches both ETH private keys AND
SHA-256 hashes AND various other 256-bit blobs. Requires context
disambiguation:

```python
ETH_HEX_RE = re.compile(r"\b(?:0x)?(?P<key>[a-fA-F0-9]{64})\b")
ETH_CONTEXT_RE = re.compile(
    r"\b(?:private[\s_-]?key|priv[\s_-]?key|signer|wallet|"
    r"mnemonic|seed|secret[\s_-]?key|sk|key)\b",
    re.IGNORECASE,
)
```

A 64-hex match is flagged only if `ETH_CONTEXT_RE` appears within
±200 characters of it. Reduces FP from "every SHA-256 hash" to
"hex blobs in obvious key contexts".

Severity: `critical` when a context word is present; otherwise the
match is **not emitted**.

#### Solana keypair JSON detector

`solana-keygen new -o keypair.json` produces a 64-element byte array:

```json
[101, 47, 9, ..., 234]   # 64 ints, each 0-255
```

Detector:

```python
SOL_KEYPAIR_RE = re.compile(
    r"\[\s*(?:\d{1,3}\s*,\s*){63}\d{1,3}\s*\]"
)
# After regex match: parse the array, verify all 64 ints are 0-255.
```

Severity: `critical`. Almost zero FP — a 64-element bounded-int array
is a very specific shape.

### Sub-module: `substrate.py`

#### Polkadot.js keystore JSON

Three-fact match. Any one of these alone is too generic; together they
identify polkadot.js with ~zero FP:

```python
def is_polkadot_js_keystore(text: str) -> bool:
    return (
        '"encoded"' in text
        and '"encoding"' in text
        and ('"pkcs8"' in text or '"sr25519"' in text or '"ed25519"' in text)
        and ('"scrypt"' in text or '"xsalsa20-poly1305"' in text)
    )
```

Severity: `high` (encrypted, but password recovery is a separate
attack). For files with the unencrypted variant (no scrypt/xsalsa20,
plain `pkcs8` content) → `critical`.

#### Substrate dev-account URIs

`//Alice`, `//Bob`, `//Charlie`, `//Dave`, `//Eve`, `//Ferdie`,
each optionally with `//stash` suffix. These are deterministic public
test keys.

```python
DEV_URI_RE = re.compile(
    r"\bkeyring\.\w*\(\s*['\"]\/\/(Alice|Bob|Charlie|Dave|Eve|Ferdie)"
    r"(\/\/stash)?['\"]"
)
```

Severity: `info` in test/fixture paths; `medium` in production paths
(`src/`, `prod/`, `main.*` modules). Path classification follows the
same `is_test_file` helper used elsewhere.

#### `subkey` CLI output

When committed in docs or scripts, `subkey generate` output is a
strong leak signal:

```
Secret phrase `bottom drive obey lake curtain smoke basket hold race lonely fit walk` is account:
  Network ID:        substrate
  Secret seed:       0xa9d6...
  Public key (hex):  0x...
  Account ID:        0x...
  SS58 Address:      5GrwvaEF...
```

Detector:

```python
SUBKEY_OUTPUT_RE = re.compile(
    r"^(\s*)(Secret seed|Secret phrase|Secret URI):\s*",
    re.MULTILINE,
)
```

Severity: `critical`.

#### SS58 addresses (informational)

```python
SS58_PATTERNS = [
    (re.compile(r"\b5[1-9A-HJ-NP-Za-km-z]{47}\b"),
     "Substrate generic SS58 address"),
    (re.compile(r"\b1[1-9A-HJ-NP-Za-km-z]{46,47}\b"),
     "Polkadot SS58 address"),  # collides with BTC P2PKH; see disambiguation
    (re.compile(r"\b[CDFGHJ][1-9A-HJ-NP-Za-km-z]{46,47}\b"),
     "Kusama SS58 address"),
]
```

Severity: `info`. SS58 collides with BTC P2PKH on the `1...` prefix —
disambiguation is best-effort: if the file imports `@polkadot` or
contains `substrate`/`polkadot`/`kusama`/`westend` strings, the match
is reported as Substrate; otherwise as ambiguous (just emit the raw
address as `info` without a chain label).

### Sub-module: `config_files.py`

JSON/YAML/.env support. Walks files of those types; for each, runs
key-value extraction and applies the cloud-provider patterns to the
*values*:

```python
# JSON: load + walk recursively, collect (path, value) where value is str.
# YAML: same via PyYAML safe_load.
# .env: split on \n, parse KEY=VALUE pairs.

# Then for each (path, value):
#   for pattern in CLOUD_PATTERNS:
#       if pattern.matches(value):
#           emit_finding(path, value, pattern)
```

Plus a name-shape match for the JSON/YAML case — if the *key* is
`api_key`, `secret`, `password`, `token`, `private_key`, `auth`,
`credential`, `bearer`, etc., AND the value is non-empty + non-
placeholder, emit a `medium` finding even without a content-pattern
match (the fact that something named `api_key` has a literal value is
itself suspicious).

### Sub-module: `entropy.py`

Generic high-entropy fallback. Runs *last*, after all named detectors,
and only on candidates that didn't match anything else.

```python
import math

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    return -sum((f / len(s)) * math.log2(f / len(s)) for f in freq.values())

def is_high_entropy_secret(s: str) -> bool:
    if len(s) < 32:
        return False
    if shannon_entropy(s) < 4.5:
        return False
    # Reject if mostly non-base64 / non-hex characters
    safe_chars = sum(1 for c in s if c.isalnum() or c in "+/=_-")
    if safe_chars / len(s) < 0.95:
        return False
    return True
```

Severity: `low` (high FP rate inherent to entropy-only matching).
Operators can suppress via `--exclude-rules entropy_generic` if they
find it noisy.

Skipped contexts: lines starting with `#`/`//`, lines that look like
comment-only documentation, files entirely consisting of generated
content (already filtered upstream by `is_generated_file`).

### Sub-module: `context.py`

Centralized FP-reduction. Mirrors `auth_check.py::SAFE_CRED_PATTERNS`:

```python
SAFE_CONTEXT = re.compile(
    r"(?:os\.(?:environ|getenv)|process\.env|Config\.|config\[|"
    r"placeholder|example|changeme|xxx|test|dummy|fake|mock|"
    r"<your.*here>|<.*>|TODO|FIXME)",
    re.IGNORECASE,
)

def is_safe_context(line: str) -> bool:
    return bool(SAFE_CONTEXT.search(line))
```

Plus path-based context — anything under `tests/`, `*_test.*`,
`fixtures/`, `**/test_data/**` is downgraded by one severity level
(critical→high, high→medium, etc.) and tagged `kind:test_fixture`.

### Severity calibration matrix

```
                           Production path     Test/fixture path
PEM unencrypted private    critical            high
PEM encrypted private      high                medium
AWS access key (live)      critical            high
GitHub PAT (ghp_...)       critical            high
Stripe sk_live_            critical            high
Stripe sk_test_            low                 info
Slack xoxb-                high                medium
JWT (any)                  medium              low
BIP-39 mnemonic            critical            high
BIP-32 xprv                critical            high
BIP-32 xpub                info                info
Bitcoin WIF                critical            high
Solana keypair JSON        critical            high
ETH private key (in ctx)   critical            high
Polkadot.js keystore       high                medium
Substrate //Alice URI      medium              info
SS58 address               info                info
subkey output              critical            high
Generic high-entropy       low                 (skipped)
```

### Performance

Per-file scan budget for the new skill:

- Walk files (already done by file_scanner) → cached
- Compile patterns once at module-import
- Per-file: ~50 cloud-provider regex applications + 1 PEM whole-file
  match + 5 crypto detectors + 4 substrate detectors + entropy fallback
  = ~60 regex evaluations on a small file

Target: < 5 ms per file on the average sub-1 KB source file. For a
10K-file repo, total scan time < 50 s. Acceptable.

Hot-path optimization: pattern grouping by first-character lookup. AWS
`AKIA...`, GitHub `ghp_`, Stripe `sk_`, Slack `xox`, etc. all have
unique 3-4 char prefixes. A pre-filter on file content
(`"AKIA" not in content` → skip AWS regex) saves ~50% of regex calls
on real corpora.

## Phases

### Phase 1 — PEM detector (highest ROI, ship first)

- [ ] 1.1.t1 — Create `agents/cwe/cwe_agent/skills/secret_scan/` package
      skeleton with `__init__.py` and `pem_blocks.py`.
- [ ] 1.1.t2 — Implement multi-line PEM-block regex + severity table.
- [ ] 1.1.t3 — File-extension override: include `.pem`, `.key`, `.crt`,
      `.cer`, `.pfx`, `.ovpn`, `.kdbx`.
- [ ] 1.1.t4 — Wire `check_secrets` as a tool exposed to the CWE agent.
- [ ] 1.1.t5 — Tests: 8 positive cases (RSA/EC/DSA/OPENSSH/PKCS8 ×
      both line-ending variants), 4 negative cases (CERTIFICATE,
      PUBLIC KEY, RSA REQUEST, garbled BEGIN with no END).

### Phase 2 — Cloud provider patterns

- [ ] 2.1.t1 — Build `CLOUD_PATTERNS` table with ~50 entries
      (AWS, GCP, GitHub, GitLab, Stripe, Slack, Twilio, SendGrid,
      Mailgun, Datadog, Heroku, Discord, Telegram, Cloudflare, …).
- [ ] 2.1.t2 — Per-pattern severity calibration matrix.
- [ ] 2.1.t3 — `kind` field per pattern (live/test/temp/id/info).
- [ ] 2.1.t4 — Hot-path prefix pre-filter (skip provider regex if its
      prefix substring isn't in the file content).
- [ ] 2.1.t5 — Tests: ~50 positive (anonymized example for each
      provider), ~10 negative (lookalikes that should NOT match).

### Phase 3 — Crypto wallet detection

- [ ] 3.1.t1 — Vendor BIP-39 English wordlist into `data/bip39_english.txt`.
- [ ] 3.1.t2 — Implement `find_mnemonics` with run-length matcher.
- [ ] 3.1.t3 — BIP-32 extended-key regex.
- [ ] 3.1.t4 — Bitcoin WIF regex + Base58 checksum verification.
- [ ] 3.1.t5 — Ethereum hex with context disambiguation.
- [ ] 3.1.t6 — Solana keypair JSON regex + range validation.
- [ ] 3.1.t7 — Tests: positive cases for each detector + negative
      (random English text shouldn't fire BIP-39; SHA-256 hash
      shouldn't fire ETH).

### Phase 4 — Substrate detection

- [ ] 4.1.t1 — Polkadot.js keystore three-fact match.
- [ ] 4.1.t2 — Substrate dev-URI regex with path-based severity.
- [ ] 4.1.t3 — `subkey` output detector.
- [ ] 4.1.t4 — SS58 detectors (Substrate / Polkadot / Kusama) with
      BTC-collision disambiguation.
- [ ] 4.1.t5 — Tests including the BTC-vs-Polkadot disambiguation
      edge case.

### Phase 5 — Config-file scanning + entropy fallback

- [ ] 5.1.t1 — `config_files.py` with JSON/YAML/.env extractors.
- [ ] 5.1.t2 — Apply `CLOUD_PATTERNS` + name-shape rules to extracted
      values.
- [ ] 5.1.t3 — `entropy.py` Shannon-entropy fallback (gated `low`
      severity).
- [ ] 5.1.t4 — `--exclude-rules entropy_generic` CLI plumbing for
      per-deployment suppression.
- [ ] 5.1.t5 — Tests: `.env` file with a leaked AWS key,
      `config.json` with `{"api_key": "AKIA..."}`, YAML with
      `stripe_key: sk_live_...`.

### Phase 6 — SKILLS.md + boundary docs

- [ ] 6.1.t1 — Update `agents/cwe/cwe_agent/skills/SKILLS.md` with the
      new `secret_scan` section and CWE coverage breakdown.
- [ ] 6.1.t2 — Document the `auth_check.py` ↔ `secret_scan` boundary
      (auth_check stays for `password = "..."`-shape; secret_scan owns
      content-pattern detection).
- [ ] 6.1.t3 — Document the git-history limitation explicitly: "Vulture
      scans the working tree only. Pair with gitleaks for git-history
      coverage."

## Tests

Each sub-module gets a dedicated test file under
`agents/cwe/tests/unit/skills/`. Per-sub-module test count:

| Sub-module | Positive | Negative |
|---|---|---|
| `pem_blocks` | 8 | 4 |
| `cloud_providers` | ~50 (one per pattern) | ~10 |
| `crypto_wallets` | 12 (BIP-39 ×3, BIP-32 ×2, WIF ×2, ETH ×2, SOL ×3) | 8 (lookalikes) |
| `substrate` | 6 | 4 |
| `config_files` | 5 (JSON / YAML / .env × cloud + name-shape) | 3 |
| `entropy` | 4 | 6 (must NOT flag legitimate hex IDs, UUIDs, hashes) |

Plus one E2E test in `agents/cwe/tests/e2e/`: scan a fixture
mini-repo containing one of every secret class. Asserts each is
detected exactly once with the correct severity.

## Risks

| Risk | Mitigation |
|---|---|
| FP rate on entropy fallback annoys operators | Default to `low` severity + `--exclude-rules entropy_generic` opt-out. Gather 2-week stability data before defaulting on. |
| BIP-39 detector fires on long blocks of mixed English text in docs | Guard: only scan code/config files (not `.md`/`.rst`); require run length exactly in {12,15,18,21,24}; require all words to be from the English wordlist (other-language wordlists not loaded). |
| BTC vs Polkadot SS58 collision on `1...` prefix | Disambiguation is best-effort. When import context is unclear, emit a chain-agnostic finding: "potential blockchain address (BTC P2PKH or Polkadot)". Operator decides. |
| New skill doubles per-file scan time | Hot-path prefix pre-filter cuts this back. Acceptance test: total CWE-agent scan time on a 10K-file repo grows ≤ 30%. |
| Secret patterns become stale (providers rotate formats) | Patterns table is a single Python file; rotation is a one-line PR. Tests cover the format string, not the validity of any specific token. |
| Vendoring the BIP-39 wordlist may have license concerns | The BIP-39 wordlist is in the public domain (per the BIP itself). Include a header note in the file linking to the BIP-39 specification. |
| Encrypted PEM keys (Proc-Type: 4,ENCRYPTED) get wrong severity | Detect the `Proc-Type: 4,ENCRYPTED` marker and downgrade to `high`. Tests cover the encrypted variant. |

## Out-of-scope follow-ups

- **Git-history scanning**: pair Vulture with gitleaks; not in 0042.
- **Encrypted-secret password cracking**: report-only.
- **Custom regex registration**: per-deployment customer-defined patterns
  via a config file. Useful but adds plumbing; defer to v1.1.
- **Severity calibration via LLM**: ask the LLM to grade each finding's
  real-world impact in context. Higher precision but burns tokens; defer.
- **License key detection** (Microsoft, JetBrains, Adobe) — different
  skill class, not in 0042.

## Open questions

- Should the entropy detector be off by default, on by default with a
  `--quiet entropy` flag, or always on but `low` severity? Lean
  off-by-default for v1.0; flip after stability data.
- Should we ship the BIP-39 wordlists for non-English languages
  (Japanese, Spanish, Chinese, French, Italian, Korean, Czech, Portuguese)?
  Adds ~100 KB of data per language. Probably defer — most leaks are
  English wordlist.
- Should public certificates (`-----BEGIN CERTIFICATE-----`) be flagged
  as `info` ("this code embeds a certificate; ensure it's not a leaked
  client cert")? Lean no — too noisy, certificates are designed to be
  public.
- Should `--exclude-rules` be per-rule (e.g. `aws_access_key`,
  `bip39_mnemonic`, `entropy_generic`) or per-class (`cloud`, `crypto`,
  `entropy`)? Lean per-rule; class-level suppression is too coarse.
