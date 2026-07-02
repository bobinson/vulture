# Vulture CWE Corpus — License

All fixtures, manifests, and the corpus runner in this directory
(`agents/cwe/tests/corpus/`) are **first-party, original works** authored for
the Vulture project as part of feature 0057 Phase 5.

They are licensed under the **Apache License, Version 2.0**, identical to the
rest of the Vulture repository.

## Provenance

- **No third-party corpora.** This corpus contains NO code from the NIST Juliet
  Test Suite, the OWASP Benchmark, SARD, or any other external dataset.
- Every positive fixture is a minimal, hand-authored example of genuinely
  vulnerable code; every clean twin is the corresponding safe rewrite of the
  same sink. They exist solely to exercise Vulture's deterministic detection
  tiers (regex skills + signatures) and to compute honest per-CWE recall /
  false-positive rates for the promotion gate (R15).
- License curation for external corpora (Juliet et al.) is deliberately
  deferred to a later phase (network access + per-sample license review).

Because everything here is first-party Apache-2.0, no entry in the repository's
`THIRD_PARTY_LICENSES.md` is required for this corpus.

    Copyright The Vulture Authors.
    Licensed under the Apache License, Version 2.0.
