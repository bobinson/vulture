# 0042 — Implementation Status

**Branch**: tbd (recommend `feat/0042-secret-scanning`)
**Status**: SHIPPED (all 6 phases; pending commit)
**Owner**: tbd
**Created**: 2026-05-02
**Target v1.0** (Phases 1+2): ~2 days
**Target v1.1** (Phases 3+4): +1.5 days
**Target v1.2** (Phases 5+6): +1 day

## Phase summary

| Phase | Status | E2E green | v1.x | Notes |
|---|---|---|---|---|
| 1 — PEM block detector | SHIPPED | — | v1.0 | Highest ROI; ships first |
| 2 — Cloud / SaaS provider patterns (~50) | SHIPPED | — | v1.0 | AWS, GitHub, Stripe, Slack, GCP, Twilio, … |
| 3 — Crypto wallet detection | SHIPPED | — | v1.1 | BIP-39 + BIP-32 + WIF + ETH + Solana |
| 4 — Substrate detection | SHIPPED | — | v1.1 | polkadot.js keystore + dev URIs + SS58 + subkey |
| 5 — Config-file scanning + entropy fallback | SHIPPED | — | v1.2 | JSON / YAML / .env + Shannon entropy |
| 6 — SKILLS.md + boundary docs | SHIPPED | — | v1.2 | Document `auth_check` ↔ `secret_scan` split |

## Detailed task list

(See `0042_implementation_plan.md` §Phases for the full numbered task
breakdown. Reproduced summary here for tracking.)

### Phase 1 — PEM blocks
- [ ] 1.1.t1 — Package skeleton + PEM detector
- [ ] 1.1.t2 — Multi-line PEM regex + severity table
- [ ] 1.1.t3 — File-extension override (`.pem`, `.key`, `.crt`, `.cer`, `.pfx`, `.ovpn`, `.kdbx`)
- [ ] 1.1.t4 — Wire `check_secrets` tool to CWE agent
- [ ] 1.1.t5 — 8 positive + 4 negative tests

### Phase 2 — Cloud providers
- [ ] 2.1.t1 — `CLOUD_PATTERNS` table (~50 entries)
- [ ] 2.1.t2 — Severity calibration matrix (live/test/temp/id/info)
- [ ] 2.1.t3 — Hot-path prefix pre-filter
- [ ] 2.1.t4 — ~50 positive + ~10 negative tests

### Phase 3 — Crypto wallets
- [ ] 3.1.t1 — Vendor BIP-39 English wordlist
- [ ] 3.1.t2 — `find_mnemonics` run-length matcher
- [ ] 3.1.t3 — BIP-32 extended-key regex
- [ ] 3.1.t4 — Bitcoin WIF + Base58 checksum verification
- [ ] 3.1.t5 — Ethereum hex with context disambiguation
- [ ] 3.1.t6 — Solana keypair JSON
- [ ] 3.1.t7 — 12 positive + 8 negative tests

### Phase 4 — Substrate
- [ ] 4.1.t1 — Polkadot.js keystore three-fact match
- [ ] 4.1.t2 — Dev-URI regex with path-aware severity
- [ ] 4.1.t3 — `subkey` output detector
- [ ] 4.1.t4 — SS58 detectors with BTC-collision disambiguation
- [ ] 4.1.t5 — 6 positive + 4 negative tests

### Phase 5 — Config files + entropy
- [ ] 5.1.t1 — JSON / YAML / .env extractors
- [ ] 5.1.t2 — Apply `CLOUD_PATTERNS` to extracted values
- [ ] 5.1.t3 — Shannon-entropy fallback (`low` severity, off by default)
- [ ] 5.1.t4 — `--exclude-rules entropy_generic` plumbing
- [ ] 5.1.t5 — 5 positive + 3 negative + 4 entropy + 6 entropy-negative tests

### Phase 6 — Docs
- [ ] 6.1.t1 — `SKILLS.md` new `secret_scan` section
- [ ] 6.1.t2 — Boundary doc: `auth_check` vs `secret_scan`
- [ ] 6.1.t3 — Git-history limitation explicit in operator docs

## Cross-cutting

- [ ] CC.1 — Cyclomatic complexity < 10 for every new function
- [ ] CC.2 — `ruff check` clean across the new package
- [ ] CC.3 — `pytest --cov=cwe_agent.skills.secret_scan` ≥ 100%
- [ ] CC.4 — Per-file scan-time overhead ≤ 5 ms on the median 1 KB source file
- [ ] CC.5 — End-to-end CWE agent scan-time growth ≤ 30% on a 10K-file repo
- [ ] CC.6 — No false positive on the Vulture repo's own source (self-test)

## Decision log

| Date | Decision | Made by |
|---|---|---|
| 2026-05-02 | Sub-module-per-class layout (`cloud_providers.py`, `pem_blocks.py`, `crypto_wallets.py`, `substrate.py`, `config_files.py`, `entropy.py`) instead of one monolithic file. Each detector class is independently testable, has its own pattern table, and can be enabled/disabled individually. | spec |
| 2026-05-02 | Phase 1 ships PEM detection in isolation — fastest unique customer value, lowest FP rate, no dependencies on the other phases. | spec |
| 2026-05-02 | File-extension override is per-skill, not a global change to `file_scanner.CODE_EXTENSIONS`. Other skills keep their existing extension lists; secret_scan adds `.pem`/`.key`/`.crt`/`.cer`/`.env` for itself only. | spec |
| 2026-05-02 | Entropy fallback ships off by default. Operators opt in via env var (`VULTURE_SECRET_SCAN_ENTROPY=true`) or per-call flag. Avoids burning operator goodwill with low-confidence findings. | spec |
| 2026-05-02 | BIP-39 wordlist: English only for v1.0. Other languages defer to a future feature; English covers the vast majority of leaks. | spec |
| 2026-05-02 | Pattern source: copy regex strings (not code) from gitleaks (MIT) and detect-secrets (Apache-2.0). Regex strings aren't copyrightable. Add a NOTICE entry for attribution courtesy. | spec |
| 2026-05-02 | `auth_check.py` stays where it is; `secret_scan` is purely additive. The two have overlapping but distinct purposes — `auth_check` covers the `name = "value"` shape; `secret_scan` covers content-pattern detection. Boundary documented in SKILLS.md. | spec |
| 2026-05-02 | Public certificates (`-----BEGIN CERTIFICATE-----`) and public keys (`-----BEGIN PUBLIC KEY-----`) are explicitly NOT flagged. They're public by design. | spec |
| TBD | Should `--exclude-rules` accept per-rule names (`aws_access_key`) or per-class names (`cloud`, `crypto`)? Open. Recommendation: per-rule. | |
| TBD | Should public addresses (BTC, ETH, SS58) be reported at all? Useful audit signal but noisy. Lean towards `info`-level. | |
| TBD | Should the LLM phase grade severity in context, or is the static calibration matrix enough? | |

## Out of scope (tracked separately)

- Git-history scanning (pair with `gitleaks`).
- Encrypted-secret password cracking (operator's responsibility).
- Customer-defined custom patterns (defer to v1.1).
- Severity grading via LLM (defer).
- License-key detection (different skill class).
- Non-English BIP-39 wordlists (defer).

## Planned follow-ups

- v1.3: customer-defined custom-pattern config (`~/.vulture/secret-rules.toml`).
- v1.4: severity grading by LLM (gated by per-finding token budget).
- v1.5: optional hash-list lookup against publicly-leaked secret databases (have-i-been-pwned-style). Useful if customer is auditing whether a leaked secret has already been disclosed.
