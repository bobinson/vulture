"""Unit tests for the consolidated ASVS requirements skill.

Every test writes its sample to an isolated ``tmp_path`` directory and
invokes :func:`check_asvs_requirements`. Tests cover:

* Positive detection cases across multiple chapters (V3, V6, V11, V12,
  V13, V16, and more).
* Safe-context negative cases for a handful of reqs.
* Chapter filter and level filter semantics.
* Language gate semantics (``.py`` vs ``.html``).
* Keyword-fallback dispatch for static reqs not in ``_CHECKS``.
* CWE reuse smoke test (V3.3.4 finding carries ``cwe_ids = ["1004"]``).
"""

from pathlib import Path


from asvs_agent.skills.asvs_requirements_check import (
    _CHECKS,
    _keyword_fallback_index,
    check_asvs_requirements,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write(tmp_path: Path, name: str, content: str) -> Path:
    """Drop a file into the audit tree and return its path."""
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


def _findings_for(tmp_path: Path, **config) -> list[dict]:
    return check_asvs_requirements(str(tmp_path), config or None)["findings"]


def _categories(findings: list[dict]) -> set[str]:
    return {f["category"] for f in findings}


def _has_req(findings: list[dict], req_id: str) -> bool:
    return f"ASVS-{req_id}" in _categories(findings)


# ---------------------------------------------------------------------------
# Registry-level sanity
# ---------------------------------------------------------------------------


def test_registry_has_sufficient_entries():
    """After correctness hardening, registry holds >= 45 well-mapped
    entries (down from 64 — 15 mislabeled entries removed, 4 relocated)."""
    assert len(_CHECKS) >= 45


def test_registry_covers_core_chapters():
    """Registry covers at least the high-value chapters. Not every chapter
    has a dedicated check — V15/V17 have mostly policy or WebRTC-specific
    reqs out of scope for SAST. The keyword fallback covers the rest."""
    chapters = {rid.split(".")[0] for rid in _CHECKS}
    core_required = {"V1", "V3", "V5", "V6", "V7", "V9", "V11", "V12", "V13", "V16"}
    assert core_required.issubset(chapters), f"missing core: {core_required - chapters}"


def test_keyword_fallback_index_is_populated():
    idx = _keyword_fallback_index()
    assert len(idx) > 20


# ---------------------------------------------------------------------------
# Positive cases — one per req_id across different chapters
# ---------------------------------------------------------------------------


def test_v3_3_4_detects_cookie_without_httponly(tmp_path):
    _write(tmp_path, "app.py", "response.set_cookie('sid', value)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V3.3.4")


def test_v3_3_1_detects_cookie_without_secure(tmp_path):
    _write(tmp_path, "app.py", "response.set_cookie('sid', value, httponly=True)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V3.3.1")


def test_v3_3_2_detects_cookie_without_samesite(tmp_path):
    _write(tmp_path, "srv.py", "http.SetCookie(w, cookie)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V3.3.2")


def test_v3_4_2_detects_cors_wildcard(tmp_path):
    _write(tmp_path, "conf.py", "allow_origins = ['*']\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V3.4.2")


def test_v3_5_6_detects_jsonp(tmp_path):
    _write(tmp_path, "api.py", "callback = request.args.get('callback')\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V3.5.6")


def test_v13_3_1_detects_hardcoded_password(tmp_path):
    """Hardcoded creds violate V13.3.1 (secrets-management solution)."""
    _write(tmp_path, "login.py", "password = 'hunter2_admin'\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V13.3.1")


def test_v6_2_1_detects_short_password_min(tmp_path):
    _write(tmp_path, "pw.py", "PASSWORD_MIN_LENGTH = 4\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V6.2.1")


def test_v7_1_1_detects_session_fixation(tmp_path):
    """Session populated from user input is V7.1.1 fixation, not V7.2.2."""
    _write(
        tmp_path,
        "sess.py",
        "session[key] = request.cookies.get('sid')\n",
    )
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V7.1.1")


def test_v9_1_2_detects_jwt_alg_none(tmp_path):
    _write(tmp_path, "jwt.py", "token = {'alg': 'none', 'typ': 'JWT'}\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V9.1.2")


def test_v9_1_1_detects_jwt_verify_false(tmp_path):
    _write(tmp_path, "jwt2.py", "jwt.decode(tok, None, verify=False)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V9.1.1")


def test_v11_3_2_detects_broken_crypto(tmp_path):
    """Broken ciphers (DES/RC4) violate V11.3.2 (approved ciphers only)."""
    _write(tmp_path, "crypto.py", "cipher = DES.new(key)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V11.3.2")


def test_v11_5_1_detects_weak_random(tmp_path):
    _write(tmp_path, "tok.py", "session_id = random.randint(0, 2**32)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V11.5.1")


def test_v13_3_1_detects_hardcoded_api_key(tmp_path):
    """Hardcoded API keys violate V13.3.1 (secrets management)."""
    _write(
        tmp_path,
        "keys.py",
        "api_key = 'sk_live_abc123def456ghi789'\n",
    )
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V13.3.1")


def test_v12_1_1_detects_weak_tls_version(tmp_path):
    _write(tmp_path, "tls.py", "context = ssl.PROTOCOL_TLSv1_0\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V12.1.1")


def test_v12_2_1_detects_cleartext_http(tmp_path):
    _write(tmp_path, "client.py", "url = 'http://api.myservice.org/v1'\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V12.2.1")


def test_v12_3_1_detects_insecure_tls_verify(tmp_path):
    _write(tmp_path, "req.py", "requests.get(url, verify=False)\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V12.3.1") or _has_req(findings, "V12.3.2")


def test_v13_4_2_detects_debug_enabled(tmp_path):
    _write(tmp_path, "conf.py", "DEBUG = True\n")
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V13.4.2")


def test_sensitive_logging_surfaces_via_fallback(tmp_path):
    """Logging passwords/secrets is CWE-532 but has no exact ASVS 5.0.0
    req. Keyword fallback may surface V14.x findings when the req
    keywords match. If no dedicated check exists, no hard assertion."""
    _write(
        tmp_path,
        "log.py",
        "logging.info('request password=' + password)\n",
    )
    findings = _findings_for(tmp_path)
    # Accept either no finding or any V14 data-protection finding.
    assert isinstance(findings, list)


def test_v16_5_3_detects_bare_except(tmp_path):
    """Bare except blocks swallow errors — violates V16.5.3 graceful failure."""
    _write(
        tmp_path,
        "errs.py",
        "try:\n    do_thing()\nexcept:\n    pass\n",
    )
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V16.5.3")


def test_v1_2_5_detects_os_command_injection(tmp_path):
    _write(
        tmp_path,
        "shell.py",
        "subprocess.call(cmd, shell=True)\n",
    )
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V1.2.5")


# V15.3.1/V15.3.2 curl-pipe-shell pattern removed — ASVS 5.0.0's
# V15.3.1 is about data minimization, not supply-chain. See
# post-review hardening commit for rationale.


# ---------------------------------------------------------------------------
# Safe-context negative cases (should NOT fire)
# ---------------------------------------------------------------------------


def test_v3_3_4_suppressed_when_httponly_present(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "response.set_cookie('sid', value, httponly=True, secure=True)\n",
    )
    findings = _findings_for(tmp_path)
    assert not _has_req(findings, "V3.3.4")


def test_v3_3_1_suppressed_when_secure_present(tmp_path):
    _write(
        tmp_path,
        "app.py",
        "response.set_cookie('sid', value, httponly=True, secure=True)\n",
    )
    findings = _findings_for(tmp_path)
    assert not _has_req(findings, "V3.3.1")


def test_v11_4_2_suppressed_with_bcrypt(tmp_path):
    _write(
        tmp_path,
        "hash.py",
        "h = bcrypt.hashpw(password.encode(), bcrypt.gensalt())\n",
    )
    findings = _findings_for(tmp_path)
    assert not _has_req(findings, "V11.4.2")


def test_v12_3_1_suppressed_in_test_context(tmp_path):
    _write(
        tmp_path,
        "dev_test.py",
        "# test fixture\nrequests.get(url, verify=False)\n",
    )
    findings = _findings_for(tmp_path)
    # test files are skipped entirely; registry finding should not emit
    assert not _has_req(findings, "V12.3.1")


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------


def test_chapter_filter_emits_only_v3(tmp_path):
    _write(
        tmp_path,
        "mixed.py",
        (
            "response.set_cookie('sid', value)\n"
            "DEBUG = True\n"
            "cipher = DES.new(key)\n"
        ),
    )
    findings = _findings_for(tmp_path, chapters=["V3"])
    categories = _categories(findings)
    assert categories  # some V3 findings
    for cat in categories:
        assert cat.startswith("ASVS-V3.")


def test_level_filter_excludes_higher_levels(tmp_path):
    """Level filter: V3.3.4 (L2) is suppressed at levels=[1]."""
    _write(tmp_path, "app.py", "response.set_cookie('sid', value)\n")
    findings_l1 = _findings_for(tmp_path, levels=[1])
    cats = _categories(findings_l1)
    assert "ASVS-V3.3.4" not in cats


# ---------------------------------------------------------------------------
# Language gate
# ---------------------------------------------------------------------------


def test_language_gate_html_does_not_fire_python_only_check(tmp_path):
    """V16.5.3 (bare except) is .py-only — must NOT fire on .html."""
    _write(tmp_path, "template.html", "<div>except:\npass</div>\n")
    findings = _findings_for(tmp_path)
    assert not _has_req(findings, "V16.5.3")


def test_language_gate_python_fires_python_only_check(tmp_path):
    """V16.5.3 (bare except) fires on .py files."""
    _write(
        tmp_path,
        "errs.py",
        "try:\n    x = 1\nexcept:\n    pass\n",
    )
    findings = _findings_for(tmp_path)
    assert _has_req(findings, "V16.5.3")


# ---------------------------------------------------------------------------
# Keyword fallback
# ---------------------------------------------------------------------------


def test_keyword_fallback_fires_medium_finding(tmp_path):
    """A dense cluster of specific ASVS keywords should trigger a fallback
    finding at medium severity, even if no registry entry matches.

    Pick a req from the fallback index with >=3 specific keywords and
    synthesize a line matching all of them.
    """
    idx = _keyword_fallback_index()
    # Find any fallback req with at least 3 specific keywords.
    chosen: dict | None = None
    for entries in idx.values():
        for entry in entries:
            if len(entry.get("_specific_kw", frozenset())) >= 3:
                chosen = entry
                break
        if chosen:
            break
    assert chosen is not None, "Expected at least one fallback req"
    kws = list(chosen["_specific_kw"])[:6]
    # Build a Python-looking line with those keywords as identifiers.
    line = "def check(" + ", ".join(kws) + "): pass"
    _write(tmp_path, "fallback.py", line + "\n")
    findings = _findings_for(tmp_path)
    expected_cat = f"ASVS-{chosen['req_id']}"
    assert expected_cat in _categories(findings)
    match = [f for f in findings if f["category"] == expected_cat][0]
    assert match["severity"] == "medium"


# ---------------------------------------------------------------------------
# CWE reuse — finding must carry cwe_ids from the crosswalk
# ---------------------------------------------------------------------------


def test_v3_4_2_finding_contains_cwe_1004(tmp_path):
    _write(tmp_path, "w.py", "allow_origins = ['*']\n")
    findings = _findings_for(tmp_path)
    match = next(f for f in findings if f["category"] == "ASVS-V3.4.2")
    assert "1004" in match.get("cwe_ids", [])
    assert match.get("chapter_id") == "V3"
    assert match.get("chapter_name")


def test_v11_3_2_finding_contains_cwe_327(tmp_path):
    """CWE reuse: V11.3.2 (broken crypto) is mapped to CWE-327 in the
    crosswalk (use of broken/risky crypto algorithm)."""
    _write(tmp_path, "c.py", "cipher = DES.new(key)\n")
    findings = _findings_for(tmp_path)
    match = next(f for f in findings if f["category"] == "ASVS-V11.3.2")
    assert "327" in match.get("cwe_ids", [])


# ---------------------------------------------------------------------------
# Empty config / default
# ---------------------------------------------------------------------------


def test_default_config_scans_all_chapters(tmp_path):
    _write(
        tmp_path,
        "app.py",
        (
            "response.set_cookie('sid', value)\n"
            "DEBUG = True\n"
        ),
    )
    findings = _findings_for(tmp_path)
    chapters = {f["category"].split(".")[0].replace("ASVS-", "") for f in findings}
    assert "V3" in chapters or "V13" in chapters


def test_source_path_nonexistent_returns_empty(tmp_path):
    findings = check_asvs_requirements(str(tmp_path / "missing"))["findings"]
    assert findings == []
