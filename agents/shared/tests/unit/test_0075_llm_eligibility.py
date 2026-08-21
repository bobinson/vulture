"""0075 — the LLM tier's two feed paths must agree on what counts as code.

The single-shot path named bare `CODE_EXTENSIONS`; the batched sweep added later
named nothing at all and so walked the DEFAULT WIDE set. Two paths feeding one
model disagreed about what counts as code — that is RC3, and the fix is that both
now name `_llm_feed_extensions()`.

RECALL SAFETY IS THE POINT OF THIS FILE. Narrowing an input set is the only change
in 0075 that can delete a true positive, so the negative controls matter more than
any positive one. Two of them were earned the hard way: an earlier revision
narrowed the feed to `CODE_EXTENSIONS`, silently dropping `.sql`/`.tf`/`.yml` and
with them three adjudicated-real CWE-732 findings; and a guard that checked the
SCANNER's set passed while that happened. The exclusion mechanism now ships EMPTY,
because the evidence for excluding `.graphql` is confounded with the unnumbered
presentation defect this feature fixes.
"""

from __future__ import annotations

from shared.tools.file_scanner import CODE_EXTENSIONS, WHITELIST_EXTENSIONS


def test_graphql_is_absent_from_the_narrow_code_set():
    """Context for the feed decision: `.graphql` is not in CODE_EXTENSIONS, which
    is why the single-shot path historically never produced these findings. That
    is a fact about the narrow set, NOT a justification for excluding the files —
    see test_the_exclusion_set_ships_empty."""
    assert ".graphql" not in CODE_EXTENSIONS
    assert ".gql" not in CODE_EXTENSIONS


def test_graphql_is_still_scanned_by_skills():
    """0075 must NOT remove `.graphql` from the scanner. Skills legitimately walk
    it via the whitelist; only the LLM PROMPT path narrows."""
    assert ".graphql" in WHITELIST_EXTENSIONS, (
        "the fix must narrow the LLM feed only — never the scanner's own coverage"
    )


def test_declarative_exclusion_does_not_touch_sql_or_terraform():
    """RECALL GUARD, asserted on the FEED — not on the scanner.

    A `.sql` file can hold a real injection or an over-broad grant; a `.tf` file
    can hold a public bucket. A fix aimed at GraphQL documents must not take them
    with it.

    This assertion earned its keep: an earlier version of it only checked
    membership in `WHITELIST_EXTENSIONS`, which is the SCANNER's set. It passed
    while the implementation had narrowed the LLM feed to `CODE_EXTENSIONS` —
    silently dropping `.sql`, `.tf`, `.hcl` and `.proto` from the model's input.
    A recall guard that tests the wrong set is worse than no guard, because it
    reports safety it never checked.
    """
    from shared.audit_runner import _llm_feed_extensions

    feed = _llm_feed_extensions()
    for ext in (".sql", ".tf", ".hcl", ".proto"):
        assert ext in feed, f"{ext} must remain in the LLM feed, not just scannable"
        assert ext in WHITELIST_EXTENSIONS, f"{ext} must remain scannable"


def test_the_exclusion_set_ships_empty():
    """The mechanism exists; the membership ships EMPTY.

    An earlier revision excluded `.graphql`/`.gql` citing "0 true positives of 32
    adjudicated". That evidence is CONFOUNDED with the defect this feature fixes:
    no skill carries GraphQL patterns, so all 32 rows had zero skill findings and
    were all in the RAW/unnumbered bucket — 12.5% precision, 78% mislocation. "0 of
    32" cannot be separated from "all 32 presented blind", so it cannot justify a
    narrowing. The 32 sites are enumerated and can be re-adjudicated under the
    numbered regime; until then nothing is excluded by default.
    """
    from shared.audit_runner import _llm_feed_extensions
    from shared.tools.file_scanner import LLM_INELIGIBLE_EXTENSIONS as _LLM_INELIGIBLE_EXTENSIONS

    assert _LLM_INELIGIBLE_EXTENSIONS == frozenset(), (
        "the exclusion must ship empty — the evidence for excluding .graphql is "
        "confounded with the unnumbered-presentation defect"
    )
    assert ".graphql" in _llm_feed_extensions(), "nothing is excluded on ship"


def test_yaml_stays_in_the_feed():
    """`.ci/jobs/*.yml` carried three adjudicated-real CWE-732 findings
    (world-writable Vault secret dirs, one under `sudo` on the production host).
    Any narrowing of the feed must keep YAML."""
    from shared.audit_runner import _llm_feed_extensions

    feed = _llm_feed_extensions()
    assert ".yml" in feed and ".yaml" in feed


def test_feed_honours_operator_added_extensions(monkeypatch):
    """`VULTURE_EXTRA_EXTENSIONS` must reach the LLM feed too.

    Caught by adversarial review of the plan: an implementation that re-unions
    `CODE_EXTENSIONS | WHITELIST_EXTENSIONS` by hand silently drops the operator's
    additions, so a team scanning `.sol` would get skill coverage and NO LLM
    coverage, with nothing to indicate why. Delegating to `default_extensions()`
    keeps one authority for "what do we scan".
    """
    from shared.audit_runner import _llm_feed_extensions

    monkeypatch.setenv("VULTURE_EXTRA_EXTENSIONS", ".sol,jsonnet")
    feed = _llm_feed_extensions()
    assert ".sol" in feed, "operator-added extension missing from the LLM feed"
    assert ".jsonnet" in feed, "leading dot must be optional, as in the scanner"


def test_feed_honours_the_whitelist_disable_hatch(monkeypatch):
    """The `VULTURE_DISABLE_EXTENSION_WHITELIST` rollback must still work for the
    LLM feed, not just for the scanner."""
    from shared.audit_runner import _llm_feed_extensions

    monkeypatch.setenv("VULTURE_DISABLE_EXTENSION_WHITELIST", "true")
    feed = _llm_feed_extensions()
    assert ".md" not in feed, "the narrow hatch must drop whitelist-only types"
    assert ".ts" in feed, "the narrow set must still carry real source"


def test_exclusion_switch_works_in_both_directions(monkeypatch):
    """The membership switch must be operable both ways: empty (the ship default)
    keeps everything, and a populated value removes exactly what it names."""
    from shared.audit_runner import _llm_feed_extensions

    monkeypatch.setenv("VULTURE_LLM_INELIGIBLE_EXTENSIONS", "")
    assert ".graphql" in _llm_feed_extensions(), "empty must keep the wide feed"

    monkeypatch.setenv("VULTURE_LLM_INELIGIBLE_EXTENSIONS", ".graphql,.gql")
    feed = _llm_feed_extensions()
    assert ".graphql" not in feed and ".gql" not in feed, "populated must exclude"
    assert ".ts" in feed and ".sql" in feed, "and must exclude nothing else"


def test_both_feed_paths_resolve_the_SAME_set():
    """The original RC3 defect, asserted at the level that matters.

    `_build_source_context` named bare CODE_EXTENSIONS while the batched sweep
    named the wide default, so the two paths feeding one model disagreed about what
    counts as code. The pre-written structural test only checks both sites *name*
    `extensions=` — it is blind to them naming DIFFERENT things.
    """
    import re
    from pathlib import Path

    import shared.audit_runner as ar

    src = Path(ar.__file__).read_text()
    named = re.findall(r"scan_code_files\(\s*source_path[^)]*extensions=([A-Za-z_]+)", src)
    assert named, "expected both feed calls to name an extension set"
    assert len(set(named)) == 1, (
        f"the feed paths resolve different sets: {sorted(set(named))} — they must "
        f"name one helper so they cannot diverge"
    )
    assert named[0] == "_llm_feed_extensions", f"expected the shared helper, got {named[0]}"


def test_the_sweep_and_the_single_shot_agree_on_the_extension_set():
    """The defect in one assertion: the two paths that feed the same model must
    resolve the same set of files.

    Pre-0075 the sweep called `scan_code_files(source_path, max_files=...)` with
    no `extensions=`, so it walked the wide set while the single-shot path walked
    the narrow one. This is a structural test because the runtime difference only
    shows up on a tree that contains declarative files.
    """
    import re
    from pathlib import Path

    import shared.audit_runner as ar

    src = Path(ar.__file__).read_text()
    calls = re.findall(r"scan_code_files\(\s*source_path[^)]*\)", src, re.DOTALL)
    feed_calls = [c for c in calls if "max_files=scan_cap" in c or "extensions=" in c]
    assert feed_calls, "expected to find the LLM feed's scan_code_files calls"
    for call in feed_calls:
        assert "extensions=" in call, (
            "every call that feeds the LLM prompt must name its extension set "
            f"explicitly, so the two paths cannot silently diverge; found: {call}"
        )


def test_prose_is_subtracted_by_default_on_budget_grounds(monkeypatch):
    """`.md`/`.txt`/`.csv` are out of the PROMPT by default, and the switch works.

    This is a BUDGET argument, not a claim that prose holds no defects — a README
    can leak a credential, which is why the skill tier keeps scanning it. The
    prompt has a fixed character ceiling and doc text displaces real source. It is
    also the contract `test_audit_runner.py:746` has always pinned: unifying the
    two feed paths onto the wide set broke that test until this subtraction landed,
    which is precisely why it is a separate, switchable concern from the
    (empty-on-ship) ineligible set.
    """
    from shared.audit_runner import _llm_feed_extensions

    feed = _llm_feed_extensions()
    for ext in (".md", ".txt", ".csv"):
        assert ext not in feed, f"{ext} must not consume prompt budget by default"
    assert ".ts" in feed and ".sql" in feed, "real source and config must stay"

    monkeypatch.setenv("VULTURE_LLM_FEED_PROSE", "true")
    widened = _llm_feed_extensions()
    assert ".md" in widened, "VULTURE_LLM_FEED_PROSE=true must restore prose"


def test_prose_is_still_scanned_by_skills():
    """The subtraction is prompt-only. A credential in a README must still be
    findable by the deterministic tier."""
    assert ".md" in WHITELIST_EXTENSIONS
    assert ".csv" in WHITELIST_EXTENSIONS


def test_extension_sets_live_in_one_module_DRY():
    """T2.10 / project rule 3. Every other extension set — `CODE_EXTENSIONS`,
    `WHITELIST_EXTENSIONS`, `WELL_KNOWN_FILENAMES`, `default_extensions()` — lives
    in `file_scanner.py`. The LLM feed's set belongs beside them, not in
    `audit_runner.py`: a reader asking "what does the LLM see?" should find the
    answer where the scanner's own sets are, and a future third feed path should
    inherit it rather than rediscover it.
    """
    from shared.tools import file_scanner as fs

    assert hasattr(fs, "llm_feed_extensions"), (
        "llm_feed_extensions() must live in file_scanner.py beside the other sets"
    )
    assert hasattr(fs, "LLM_PROSE_EXTENSIONS")
    assert hasattr(fs, "LLM_INELIGIBLE_EXTENSIONS")

    # audit_runner must DELEGATE, not re-derive.
    import inspect

    from shared import audit_runner as ar

    src = inspect.getsource(ar)
    assert "default_extensions()" not in src, (
        "audit_runner must not rebuild the feed set; it must call "
        "file_scanner.llm_feed_extensions()"
    )


def test_relocated_helper_preserves_every_behaviour():
    """The move must be behaviour-preserving: same ship defaults, same switches."""
    from shared.tools.file_scanner import LLM_INELIGIBLE_EXTENSIONS, llm_feed_extensions

    feed = llm_feed_extensions()
    assert LLM_INELIGIBLE_EXTENSIONS == frozenset(), "still ships empty"
    assert ".graphql" in feed, "nothing excluded on ship"
    assert ".md" not in feed, "prose still subtracted on budget grounds"
    for ext in (".sql", ".tf", ".hcl", ".proto", ".yml", ".ts"):
        assert ext in feed, f"{ext} must survive the move"
    assert isinstance(feed, frozenset), "must stay hashable for the lru_cache key"
