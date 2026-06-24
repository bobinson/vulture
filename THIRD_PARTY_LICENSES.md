# Third-Party Licenses

Vulture itself is licensed under the Apache License 2.0 (see [LICENSE](LICENSE)).
This document records every body of third-party content redistributed in this
repository, the upstream license that governs it, and the modifications, if any,
that have been applied. The summary form of these notices is in [NOTICE](NOTICE);
this file is the authoritative long form.

For runtime *dependencies* (Go modules, Python packages, npm packages),
see the dependency manifests:
- Go backend: [`backend/go.mod`](backend/go.mod), [`cli/go.mod`](cli/go.mod)
- Python agents: [`agents/*/pyproject.toml`](agents/)
- Frontend: [`frontend/package.json`](frontend/package.json)

All current runtime dependencies use permissive OSI-approved licenses (Apache-2.0,
MIT, BSD-3-Clause, BSD-2-Clause). No GPL/AGPL/SSPL or non-OSI licenses are pulled
in by the lockfiles as of the v0.1.0 release.

**One exception, scoped:** the optional bundled Semgrep plugin
(`plugins/semgrep/`) ships a Dockerfile that pulls the upstream
`semgrep/semgrep` Docker image. Semgrep is LGPL-2.1-only. It runs as a
separate process in its own container and communicates with Vulture
exclusively over HTTP/SSE — no static linking, no in-process loading.
The Apache-2.0 Vulture code is therefore not a derivative work of
Semgrep. See section 5 below for the full attribution and the
dynamic-linking rationale.

---

## 1. MITRE CWE™ (Common Weakness Enumeration)

**What:** A community-developed list of common software and hardware weakness types,
maintained by The MITRE Corporation.

**Upstream version vendored:** CWE 4.19.1.

**Upstream URL:** https://cwe.mitre.org/

**License / terms:** [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
Copyright © 2006-2025 The MITRE Corporation. All rights reserved. The CWE Terms of
Use permit redistribution provided that the MITRE copyright notice and attribution
to MITRE are retained and made visible to users of derivative works.

**What we redistribute:**
- `agents/cwe/cwe_agent/data/cwe_catalog.json` — a flat lookup JSON derived from
  the upstream `cwec_v4.19.1.xml`. Field names preserve the upstream attribute
  vocabulary; copyright attribution is preserved at the catalog-file level via
  [`agents/cwe/cwe_agent/data/LICENSE.md`](agents/cwe/cwe_agent/data/LICENSE.md).

**What we do NOT redistribute (replaced by pointer files):**
- The raw upstream XML (`cwec_v4.19.1.xml`).
- The human-readable PDF (`cwec_v4.19.1.pdf`).
- The XSD schema (`cwe_schema_latest.xsd`).

The pointer files under [`docs/features/0014_cwe_version_4.19.1/`](docs/features/0014_cwe_version_4.19.1/)
and [`docs/features/0010_cwe_audit/`](docs/features/0010_cwe_audit/) document the
upstream URLs, versions, and SHA-256 checksums needed to fetch a local copy if you
want to regenerate `cwe_catalog.json` from scratch or audit the transformation.

**Modifications applied:** XML → JSON transformation; `Observed_Examples` extracted
into a structured field; `tech_words` synonym index added; taxonomic rollup helpers
added for Class/Pillar parents. None of the modifications alter, omit, or
contradict the upstream weakness descriptions.

---

## 2. OWASP Application Security Verification Standard (ASVS) v5.0.0

**What:** A list of application security verification requirements maintained by
the OWASP Foundation, organized into 17 chapters and three verification levels.

**Upstream version vendored:** ASVS 5.0.0.

**Upstream URL:** https://github.com/OWASP/ASVS

**License / terms:** Creative Commons Attribution-ShareAlike 4.0 International
([CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/)). Copyright ©
The OWASP Foundation and contributors.

CC BY-SA 4.0 obligations on the redistributed data files:
1. **Attribution** — credit the OWASP Foundation and link to ASVS upstream.
2. **License notice** — provide a link to CC BY-SA 4.0.
3. **Indication of changes** — declare what was modified.
4. **ShareAlike** — derivative works of the ASVS *content* must be licensed under
   CC BY-SA 4.0 (or a later compatible CC version). This applies to the data
   files in `agents/asvs/asvs_agent/data/` only; the rest of Vulture (Apache-2.0
   code) is not a derivative of ASVS content.

**What we redistribute** (under CC BY-SA 4.0; see also
[`agents/asvs/asvs_agent/data/LICENSE.md`](agents/asvs/asvs_agent/data/LICENSE.md)):
- `agents/asvs/asvs_agent/data/asvs_source.json` — direct upstream extraction.
- `agents/asvs/asvs_agent/data/asvs_catalog.json` — reorganized lookup form.
- `agents/asvs/asvs_agent/data/asvs_cwe_crosswalk.json` — LLM-assisted mapping
  from each ASVS req_id to one or more CWE IDs (the upstream v5.0.0 dropped the
  CWE column; this is our reconstruction). Considered a derivative.
- `agents/asvs/asvs_agent/data/asvs_detectability.json` — per-requirement
  classification into `static` / `runtime` / `policy`. Considered a derivative.

**Modifications applied:** transformation to lookup JSON; addition of CWE
crosswalk; addition of detectability classification. The text of each requirement
is preserved verbatim where included.

---

## 3. NIST SP 800-218 — Secure Software Development Framework (SSDF)

**What:** NIST's recommended set of secure software development practices.

**Upstream version vendored:** SSDF v1.1.

**Upstream URL:** https://csrc.nist.gov/Projects/ssdf

**License / terms:** Works of the U.S. federal government are public-domain in
the United States (17 USC §105). NIST publications carry no copyright restriction
on use, reproduction, or redistribution.

**What we redistribute:**
- `agents/ssdf/ssdf_agent/practice_groups/` — the SSDF practice groups (PO, PS,
  PW, RV) and per-practice rules used by the SSDF agent.

**Modifications applied:** the SSDF text is parsed into structured Python
modules; section numbers and identifiers are preserved.

---

## 4. Semgrep CLI (bundled plugin)

**What:** A multi-language static-analysis tool for finding bugs and
security issues. Vulture ships a bundled reference plugin
(`plugins/semgrep/`) that wraps the upstream Semgrep CLI behind the
Vulture plugin contract.

**Upstream version vendored:** none — the plugin's Dockerfile pulls the
upstream `semgrep/semgrep:1.84.0` Docker image at build time. No
Semgrep source is committed to this repository.

**Upstream URL:** https://github.com/semgrep/semgrep

**License / terms:** GNU Lesser General Public License v2.1
([LGPL-2.1-only](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)).
Copyright © Semgrep, Inc. and contributors.

**Dynamic-linking rationale (why Apache-2.0 Vulture code is not a
derivative work of LGPL-2.1 Semgrep):**

1. Semgrep is invoked as a **separate process** running in its own
   container. Vulture does not link Semgrep's libraries into its own
   address space.
2. Communication is over the network: Vulture POSTs an audit request
   to the plugin's `/run` endpoint and consumes an SSE stream. No
   shared memory, no FFI, no dynamic library load.
3. The plugin wrapper at `plugins/semgrep/src/wrapper.py` is
   Apache-2.0-licensed Vulture code; it executes the Semgrep CLI via
   `subprocess.run`. Treating subprocess invocation as a derivative
   work would make every Unix shell pipeline a derivative work of
   every program it runs — that interpretation has been consistently
   rejected by the FSF and by the courts.
4. The LGPL-2.1 distribution obligations therefore apply to **the
   Semgrep image itself** (which carries its own LGPL-2.1 license text
   inside the container), not to Vulture.

**Operator obligations:** if you modify the Semgrep CLI itself, you
must comply with LGPL-2.1 at the container layer (publish your
modified Semgrep source, retain copyright notices, etc.). Modifying
the Vulture wrapper around it is purely Apache-2.0.

**What we redistribute:** the plugin manifest (`plugin.toml`), the
wrapper code, the Dockerfile, the rule-to-CWE map. Not the Semgrep
binary itself, not Semgrep source.

**Modifications applied:** none. The plugin invokes `semgrep scan
--json` with operator-specified rule packs and translates the JSON
output into Vulture's finding shape.

---

## 5. Runtime dependencies (summary)

The full transitive list is generated by the package managers (`go list -m all`,
`pip-licenses`, `npm ls`); a current SBOM may be attached to the GitHub release.

Direct dependencies of note:

**Go backend / CLI:**
- `github.com/google/uuid` — BSD-3-Clause
- `github.com/lib/pq` — MIT
- `golang.org/x/crypto` — BSD-3-Clause
- `modernc.org/sqlite` — BSD-3-Clause

**Python agents (via `agents/shared/pyproject.toml`):**
- `fastapi`, `pydantic`, `openai-agents`, `litellm`, `tiktoken` — MIT
- `uvicorn`, `httpx`, `sse-starlette` — BSD-3-Clause

**Frontend:**
- `react`, `react-dom`, `react-router-dom`, `i18next` — MIT
- `vite`, `vitest`, `@playwright/test` — MIT
- `tailwindcss` — MIT

**Copyleft status (corrected 2026-06-24).** The Python / Go / npm *application*
dependencies in the lockfiles are permissive (MIT / BSD / Apache-2.0). The earlier
blanket "no copyleft present" statement was **inaccurate and is withdrawn**: the
bundled Semgrep plugin is LGPL-2.1 (see NOTICE), and the **bundled native-install
runtime** (§6) ships a GPL-3.0 component on macOS.

---

## 6. Bundled native-install runtime (Mode E tarballs)

`release.yml` bundles a python-build-standalone (PBS) CPython 3.12 runtime into
every native-install tarball (`runtime/python/`), so the components below are
**redistributed in the release binaries** and must be attributed. Inventory
verified 2026-06-24 against the pinned build `cpython-3.12.13+20260610`
(SHA-matched to `scripts/pbs-shas-20260610.txt`).

| Component | Version | License | Where |
|-----------|---------|---------|-------|
| CPython | 3.12.13 | PSF License Agreement | the interpreter |
| OpenSSL | 3.x | Apache-2.0 | `_ssl`, `_hashlib` |
| SQLite | 3.x | public domain | `_sqlite3` |
| zlib | 1.3.1 | zlib | `zlib` |
| xz / liblzma | 5.x | 0BSD / public domain | `_lzma` |
| bzip2 | 1.0.8 | bzip2 (BSD-like) | `_bz2` |
| libffi | — | MIT | `_ctypes` |
| expat | 2.8.1 | MIT | `pyexpat` |
| libmpdec | 2.5.x | BSD-2-Clause | `_decimal` |
| ncurses | 6.5 | MIT/X11-style | `_curses` |
| **libedit** | — | BSD-2-Clause | `readline` — **NOT** GNU readline (no GPL) |
| Tcl/Tk | 9.0 | Tcl/Tk (BSD-style) | `_tkinter` (`libtcl9*.so`) |
| ~~Berkeley DB / GNU gdbm~~ | — | — | **REMOVED** — these backed `_dbm` (`dbm.ndbm`): Berkeley DB on Linux, **GPL-3.0 GNU gdbm on macOS**. `_dbm.*.so` is now **stripped on every platform** at build. See ✅ below. |

> **✅ Resolved (2026-06-24) — `_dbm` is stripped at build.** The macOS PBS
> `_dbm.cpython-312-darwin.so` statically linked **GNU gdbm (GPL-3.0)** as its ndbm
> backend (Linux used Berkeley DB / Sleepycat). Since nothing in Vulture uses
> `dbm.ndbm` (`dbm.open()` falls back to the pure-Python `dbm.dumb`),
> `build-release.sh` now **removes `_dbm.*.so` from the bundled runtime on every
> platform** via `strip_copyleft_modules` (`scripts/lib/runtime_strip.sh`), and
> `assert_no_copyleft_native` **hard-fails the build** if any GPL/AGPL native code
> remains. Result: **every release tarball is permissive-only** — verified against
> the real macOS `_dbm.so`, guarded by `scripts/tests/test_runtime_strip.sh`.

PBS `install_only` archives ship only CPython's own `LICENSE.txt` — not the
upstream libraries' license texts. Source those from the full PBS build's
`licenses/` manifest (or upstream) and vendor them for completeness.
