# Third-party rule set `gitlab`

Vendored verbatim by `plugins/opengrep/tools/vendor_rules.py`; never edit these files
by hand. To bump the set, follow `plugins/opengrep/tools/README.md`.

- Upstream: https://gitlab.com/gitlab-org/security-products/sast-rules
- Commit: `9c375dc49a7cd431e2b95c2620af651ef1d096a4`
- Folders: `csharp/`, `go/`, `java/`, `javascript/`, `python/`, `scala/`
- Rule files: 263 (Apache-2.0: 26, MIT: 237)
- Licence texts: `LICENSE`, `LICENSE-APACHE-2.0`

## Notes

- Only the top-level language folders listed above are vendored. Never vendored: c/ (GPL-2.0), rules/lgpl/ (LGPL-3.0), rules/lgpl-cc/ (Commons Clause), rules/gitlab/ (GitLab EE licence), mappings/, qa/, spec/, ci/, scripts/, and every sample source file.
- Every vendored file carries GitLab's `# License:` header. The 26 go/ files whose header reads `Apache 2.0 (c) gosec` are derived from gosec (https://github.com/securego/gosec) and are Apache-2.0 (LICENSE-APACHE-2.0); all other files are MIT (LICENSE).
- Six javascript/ rules name an eslint-plugin-security rule as `source-rule-url`: the detection they re-implement in Semgrep syntax. They carry GitLab's MIT header.
- Lineage cross-check: --lineage-corpus was a local clone of opengrep-rules (a fork of semgrep-rules) at f1d2b562b414783763fd02a6ed2736eaed622efa. The six python/ rules it excluded check what Bandit checks and their messages are GitLab's own, so the shared logic may be common ancestry; they are left out because their provenance cannot be shown.

## Excluded (7)

| File | Reason |
| --- | --- |
| `csharp/crypto/rule-CertificateValidationDisabled.yml` | Opengrep 1.33.1 rejects it: rule parse error (invalid C# pattern) |
| `python/bind_all_interfaces/rule-general-bindall-interfaces.yml` | all 3 pattern clauses found in lineage-corpus rule python/lang/security/audit/network/bind.yaml |
| `python/crypto/rule-crypto-encrypt-ec.yml` | all 5 pattern clauses found in lineage-corpus rule python/cryptography/security/insufficient-ec-key-size.yaml |
| `python/deserialization/rule-marshal.yml` | all 4 pattern clauses found in lineage-corpus rule python/lang/security/audit/marshal.yaml |
| `python/ssh/rule-ssh-nohost-key-verification.yml` | all 3 pattern clauses found in lineage-corpus rule python/lang/security/audit/paramiko-implicit-trust-host-key.yaml |
| `python/ssl/rule-req-no-certvalid.yml` | all 8 pattern clauses found in lineage-corpus rule python/requests/security/disabled-cert-validation.yaml |
| `python/ssl/rule-ssl-with-bad-version.yml` | all 9 pattern clauses found in lineage-corpus rule python/lang/security/audit/weak-ssl-version.yaml |
