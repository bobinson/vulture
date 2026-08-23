"""ASVS V5.1.1 must require a filesystem SINK, and registry findings must not
fire once per LINE.

Measured through the real agent path (`vulture scan ~/src/togetherapp --types asvs`):
504 of 517 ASVS findings — 97.5%, all HIGH — were V5.1.1. Sampling them showed
the same shape every time: an ordinary relative import.

    import { loadEnv } from '../env';
    export { x } from '../../shared/types';
    const m = require('../lib/util');

Two independent defects:

F1. PATH_TRAVERSAL_PATTERNS carried a BARE `re.compile(r'\\.\\./')`. Its five
    siblings all require a filesystem accessor (`open(...request...)`,
    `readFile(...req...)`, `os.path.join(...input...)`); this one required
    nothing. `../` is the ordinary spelling of a relative module path in
    JS/TS — not evidence of traversal. Verified before the fix: the bare pattern
    (index 1) matched all three imports above, while the genuine traversal
    `fs.readFile(path.join(base, req.params.name))` matched the sink pattern
    (index 5) instead — so removing the bare literal costs no true positive of
    that shape.

F2. `_scan_line_registry` appended a finding per matching LINE, while its
    sibling `_scan_line_keyword_fallback` already took a `seen_per_file` set and
    documented "Each req fires at most once per file to avoid noise". A file
    with 40 relative imports produced 40 identical HIGH rows. This is the
    amplifier that turned a per-file defect into a per-line flood.

The regression guard matters as much as the suppression: the sink-bearing
traversal shapes must still fire, or this trades noise for blindness.
"""

import tempfile
from pathlib import Path

import pytest
from asvs_agent.skills._cwe_patterns import PATH_TRAVERSAL_PATTERNS
from asvs_agent.skills.asvs_requirements_check import check_asvs_requirements


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_asvs_requirements(str(root))["findings"]


def _v511(findings) -> list[dict]:
    return [f for f in findings if "V5.1.1" in (f.get("title", "") + f.get("check_id", ""))]


# ── F1: relative module specifiers are not traversal ──────────────────────


RELATIVE_IMPORTS = {
    "esm_import.ts": "import { loadEnv } from '../env';\nexport const a = loadEnv();\n",
    "esm_reexport.ts": "export { x } from '../../shared/types';\n",
    "cjs_require.js": "const m = require('../lib/util');\nmodule.exports = m;\n",
    "dynamic_import.ts": "const mod = await import('../frontend/lib/qa/seed-runner');\n",
    "css_import.css": "@import '../styles/base.css';\n",
}


@pytest.mark.parametrize("name", sorted(RELATIVE_IMPORTS))
def test_relative_import_is_not_path_traversal(name):
    findings = _v511(_run({name: RELATIVE_IMPORTS[name]}))
    assert findings == [], f"{name}: relative import reported as V5.1.1 traversal"


def test_bare_traversal_literal_is_gone_from_the_pattern_list():
    """Pattern level, so the fix cannot regress behind the safe-context arm."""
    for line in ["import x from '../env';", "from '../../a/b'"]:
        hits = [p.pattern for p in PATH_TRAVERSAL_PATTERNS if p.search(line)]
        assert hits == [], f"{line!r} still matches traversal pattern(s): {hits}"


def test_many_imports_in_one_file_do_not_multiply():
    """F1+F2 together: the measured shape was a .tsx file with dozens of
    relative imports producing one HIGH row each."""
    body = "".join(f"import m{i} from '../mod{i}';\n" for i in range(40))
    assert _v511(_run({"many.tsx": body})) == []


# ── F1 regression guard: real traversal must still fire ───────────────────


TRUE_POSITIVES = {
    "read_join.js": "fs.readFile(path.join(base, req.params.name), cb);\n",
    "open_concat.py": "def h(request):\n    return open('../' + request.args['f']).read()\n",
    "sendfile.js": "res.sendFile('../uploads/' + req.query.file);\n",
    "ospath_join.py": "import os\ndef h(request):\n    return os.path.join(UPLOAD_DIR, request.form['filename'])\n",
}


@pytest.mark.parametrize("name", sorted(TRUE_POSITIVES))
def test_real_traversal_still_detected(name):
    findings = _run({name: TRUE_POSITIVES[name]})
    assert findings, f"{name}: a genuine traversal/sink shape produced NO finding at all"


def test_traversal_with_sink_on_same_line_detected():
    body = "const p = '../' + req.query.f;\nfs.readFileSync('../' + req.query.f);\n"
    assert _run({"sink.js": body}), "traversal literal beside a sink must still fire"


# ── F2: one finding per requirement per file ───────────────────────────────


def test_registry_requirement_fires_once_per_file():
    """Five cookie violations in one file must yield ONE row, matching the
    policy the keyword-fallback path already documents."""
    body = "".join(
        f"res.cookie('sid{i}', v{i}, {{ httpOnly: false }});\n" for i in range(5)
    )
    findings = _run({"cookies.js": body})
    per_req: dict[str, int] = {}
    for f in findings:
        key = f.get("check_id") or f.get("title", "")
        per_req[key] = per_req.get(key, 0) + 1
    dupes = {k: n for k, n in per_req.items() if n > 1}
    assert not dupes, f"a requirement fired more than once for one file: {dupes}"


def test_dedup_does_not_leak_across_files():
    """The seen-set must be per FILE, or the second file's real violation is
    silently swallowed."""
    body = "res.cookie('sid', v, { httpOnly: false });\n"
    findings = _run({"a.js": body, "b.js": body})
    files = {f["file_path"] for f in findings}
    assert len(files) == 2, f"expected a finding in each file, got {sorted(files)}"


def test_distinct_requirements_in_one_file_both_reported():
    """Dedup is per-requirement, never per-file-global."""
    body = (
        "res.cookie('sid', v, { httpOnly: false });\n"
        "const ctx = ssl.CERT_NONE;\n"
        "requests.get(url, verify=False)\n"
    )
    findings = _run({"multi.js": body})
    keys = {f.get("check_id") or f.get("title", "") for f in findings}
    assert len(keys) >= 2, f"expected multiple distinct requirements, got {keys}"


def test_reported_line_is_the_first_match():
    """With per-file dedup the surviving row must still point somewhere useful."""
    body = "const ok = 1;\n" * 3 + "res.cookie('sid', v, { httpOnly: false });\n" * 2
    findings = [f for f in _run({"first.js": body}) if "3.3" in (f.get("title", "") + f.get("check_id", ""))]
    if findings:
        assert findings[0]["line_start"] == 4, (
            f"expected the FIRST matching line (4), got {findings[0]['line_start']}"
        )


def test_rollback_flag_restores_bare_traversal(monkeypatch):
    """Assert through the REAL entry point, not the module pattern list.

    The first version of this test asserted on
    `_cwe_patterns.PATH_TRAVERSAL_PATTERNS`, so it passed while the behaviour it
    stood for did not hold — the skill consults a union built at import, and the
    V5.1.1 safe-context arm (the other half of F1) answered to no flag at all.

    Scope, stated precisely: the flag governs the traversal PATTERN set and the
    relative-specifier safe-context arm. It does NOT re-enable scanning of
    import lines — those are excluded by `_line_is_scannable` (F3), a separate
    fix with its own rationale.
    """
    import importlib
    import sys

    monkeypatch.setenv("VULTURE_ASVS_DISABLE_TRAVERSAL_SINK_GATE", "true")
    for mod in [m for m in list(sys.modules) if m.startswith("asvs_agent")]:
        del sys.modules[mod]
    try:
        from asvs_agent.skills.asvs_requirements_check import (
            check_asvs_requirements as rolled_back,
        )
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "r.ts").write_text("const p = '../config/app.json';\n")
            restored = rolled_back(d)["findings"]
        assert restored, "rollback must restore the pre-fix bare-traversal match"
    finally:
        # Leave no mutated module state for the rest of the session.
        monkeypatch.delenv("VULTURE_ASVS_DISABLE_TRAVERSAL_SINK_GATE", raising=False)
        for mod in [m for m in list(sys.modules) if m.startswith("asvs_agent")]:
            del sys.modules[mod]
        importlib.import_module("asvs_agent.skills.asvs_requirements_check")


def test_bare_traversal_not_reported_by_default():
    """The same fixture with the gate ON — the pair is what makes the rollback
    test meaningful."""
    assert _run({"r.ts": "const p = '../config/app.json';\n"}) == []


# ── the same missing-boundary defect in a sibling pattern ─────────────────


def test_identifier_ending_in_path_is_not_traversal():
    """`Path\\(` without a left boundary matched the TAIL of any identifier
    ending in "Path", so `resolveCompletionPath(user, url)` was reported as
    path traversal — the single V5.1.1 row that survived the sink gate on the
    measured target, and a false positive too. Same defect as DROP matching
    inside "backdrop-filter" in CWE-89."""
    for line in [
        "  return resolveCompletionPath(user, resolvedUrl);",
        "  const p = getPath(user);",
        "  const out = buildPath(req.query.x);",
    ]:
        hits = [p.pattern for p in PATH_TRAVERSAL_PATTERNS if p.search(line)]
        assert hits == [], f"{line.strip()!r} still matches: {hits}"


def test_pathlib_path_constructor_still_detected():
    """The boundary must not blind the detector to real pathlib usage: '.' is
    outside the lookbehind class, so `pathlib.Path(` still matches."""
    for line in [
        '    return Path(request.args["f"])',
        "    return pathlib.Path(user_input)",
    ]:
        assert any(p.search(line) for p in PATH_TRAVERSAL_PATTERNS), (
            f"{line.strip()!r} must still match a traversal pattern"
        )


# ── B3: the import arm must veto only a relative SPECIFIER ────────────────
#
# It guards the WHOLE _PATH_TRAVERSAL_UNION, so anchoring it on line SHAPE
# (a leading `export`, a bare `require(`) silently vetoed genuine traversal in
# the commonest TS shapes. All four below were detected before the arm existed
# and missed after it.


EXPORTED_SINKS = {
    "arrow.ts": "export const load = (f) => fs.readFileSync('../uploads/' + f);\n",
    "func.ts": "export function read(req) { fs.readFile('../' + req.query.f, cb); }\n",
    "default.ts": "export default (req) => res.sendFile('../uploads/' + req.query.file);\n",
    "requirepath.ts": "const p = require('path').join(base, '../' + req.query.f);\n",
}


@pytest.mark.parametrize("name", sorted(EXPORTED_SINKS))
def test_exported_handler_traversal_still_detected(name):
    assert _run({name: EXPORTED_SINKS[name]}), (
        f"{name}: the import/export safe-context arm vetoed a genuine traversal"
    )


# ── B4: both directions, and no dead branches ─────────────────────────────


def test_sink_after_traversal_direction_is_live():
    """Appending `\\s*\\(` to the whole accessor alternation made the entries that
    already ended in `(` or `.` unsatisfiable (`Path((`, `stat((`, `shutil.(`),
    silently killing the Python file-API half of the promised 'either order'."""
    for line in [
        "q = '../' + name; Path(q).read_text()",
        "q = '../' + n; stat(q)",
        "q = '../' + n; shutil.copy(q, d)",
    ]:
        assert any(p.search(line) for p in PATH_TRAVERSAL_PATTERNS), line


def test_accessor_must_be_a_call_not_an_identifier_prefix():
    """An unanchored `open` under IGNORECASE matched inside identifiers, which
    re-admitted the very FP class this change removes."""
    for line in [
        "const go = () => openDialog('../assets/a.png')",
        "const x = reopenModal('../a/b');",
    ]:
        hits = [p.pattern for p in PATH_TRAVERSAL_PATTERNS if p.search(line)]
        assert hits == [], f"{line!r} matched: {hits}"


# ── F3: line/file context guards ──────────────────────────────────────────


def test_prose_file_is_not_scanned():
    """A hardening guide DESCRIBES controls; it does not implement them. The
    keyword fallback is especially exposed because it scores a line by word
    overlap against requirement prose, so documentation about a requirement
    matches that requirement almost by construction."""
    body = (
        "# Security hardening\n\n"
        "Applications must not store passwords using MD5.\n"
        "Never set `verify=False` on an HTTPS request.\n"
        "Session tokens must expire and the user must re-authenticate.\n"
    )
    assert _run({"SECURITY.md": body}) == []


def test_import_line_is_not_scannable():
    assert _run({"imports.ts": "import { a } from '../x';\nexport { a };\n"}) == []


def test_english_prose_inside_a_string_does_not_score():
    """The keyword fallback must not read requirement prose out of a log
    message."""
    body = (
        "export function f() {\n"
        "  logger.info('session token expired, user must re-authenticate');\n"
        "}\n"
    )
    assert _run({"log.ts": body}) == []


def test_registry_patterns_still_match_inside_strings():
    """The strip is scoped to the keyword fallback: registry patterns
    legitimately match string contents, and stripping there would blind them."""
    body = 'const opts = { rejectUnauthorized: false };\nrequests.get(url, verify=False)\n'
    assert _run({"cfg.js": body}), "a real in-string config violation must still fire"
