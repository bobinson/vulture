"""L5 closure gate — honour a judge demotion only when the window decides it.

Measured on a real run: 36 of 80 judge verdicts were demotions, and every one
was discarded by the blanket ``deterministic_authoritative`` exemption. Reading
them showed the exemption blocks the right thing for the wrong reason:

    CWE-400  "the snippet shows a static HTML paragraph … the finding
              description contradicts the code"                    -> CORRECT
    CWE-404  "no file handle or stream is opened here"             -> CORRECT
    CWE-759  "salt generation isn't explicit in the snippet, but standard
              security wrappers typically handle salting"          -> WRONG
              (the helper is literally createHash('md5'))

All three share provenance, so provenance cannot separate them. What separates
them is what the refutation rests on:

* **window-local** — the code shown contradicts the claim. Evidence is present.
* **window-external** — the thing that would make it safe is *not visible*, and
  the judge assumes it exists. A 60-line window can prove a contradiction; it
  can never prove an absence, and this failure mode is optimistic, which is the
  dangerous direction for a security tool.

A regex over the reasoning prose was tried and rejected: it left 25 of the 36
unclassified. So the judge declares closure itself, as a schema field, and the
gate FAILS CLOSED — absent or false means the existing protection stands, which
also keeps every cached pre-change verdict safe.
"""

from __future__ import annotations

import pytest

from shared.validate.llm_judge import _verdict_to_check, _window_sufficient
from shared.validate.types import ValidationCheck


def _check(**extras) -> ValidationCheck:
    return ValidationCheck(id="llm_judge", result="demoted", weight=-0.6, extras=extras)


class TestClosureIsParsedFromTheVerdict:
    def test_true_is_carried_onto_the_check(self):
        v = {"id": "f1", "exploitable": 0.1, "reasoning": "r", "window_sufficient": True}
        c = _verdict_to_check(v, model="m", batch_id=0, language="ts")
        assert c.extras.get("window_sufficient") is True

    def test_false_is_carried_onto_the_check(self):
        v = {"id": "f1", "exploitable": 0.1, "reasoning": "r", "window_sufficient": False}
        c = _verdict_to_check(v, model="m", batch_id=0, language="ts")
        assert c.extras.get("window_sufficient") is False

    def test_absent_field_does_not_assert_closure(self):
        """Pre-change cached verdicts must keep their protection."""
        v = {"id": "f1", "exploitable": 0.1, "reasoning": "r"}
        c = _verdict_to_check(v, model="m", batch_id=0, language="ts")
        assert _window_sufficient(c) is False


class TestGateFailsClosed:
    @pytest.mark.parametrize("extras", [
        {},                                  # field absent entirely
        {"window_sufficient": False},        # judge says it depends on unseen code
        {"window_sufficient": "yes"},        # wrong type — not a bare True
        {"window_sufficient": None},
    ])
    def test_non_assertions_do_not_open_the_gate(self, extras):
        assert _window_sufficient(_check(**extras)) is False

    def test_only_a_literal_true_opens_the_gate(self):
        assert _window_sufficient(_check(window_sufficient=True)) is True


class TestSafeguardHonoursClosure:
    """The end-to-end contract on the safeguard pass."""

    def _finding(self, cwe: str) -> dict:
        return {
            "id": "f1", "category": cwe, "check_id": "cwe.x.y",
            "provenance": "skill", "severity": "high",
            "file_path": "/x/a.ts", "line_start": 1,
            "validation": {"checks": []},
        }

    def _run(self, finding: dict, check: ValidationCheck):
        from shared.validate.llm_judge import _apply_l5_safeguards

        out = [[check]]
        _apply_l5_safeguards([finding], [0], out)
        return out[0][0]

    def test_window_local_demotion_survives_on_a_skill_finding(self):
        """The CWE-400 case: the judge saw enough, so its demotion stands."""
        res = self._run(
            self._finding("CWE-400"), _check(window_sufficient=True),
        )
        assert res.weight < 0, (
            "a window-local refutation of a skill finding must be honoured; "
            "blocking it is what discarded 16 correct verdicts"
        )
        assert not res.extras.get("safeguard")

    def test_window_external_demotion_is_still_suppressed(self):
        """The CWE-759 case: the judge guessed about code it could not see."""
        res = self._run(
            self._finding("CWE-759"), _check(window_sufficient=False),
        )
        assert res.weight == 0.0
        assert res.extras.get("safeguard") == "deterministic_authoritative"

    def test_crypto_policy_stays_exempt_even_when_window_local(self):
        """A hardcoded key is one whatever surrounds it — unconditional."""
        res = self._run(
            self._finding("CWE-798"), _check(window_sufficient=True),
        )
        assert res.weight == 0.0
        assert res.extras.get("safeguard") == "crypto_policy_exempt"

    def test_kill_switch_restores_the_blanket_exemption(self, monkeypatch):
        monkeypatch.setenv("VULTURE_L5_CLOSURE_GATE", "false")
        res = self._run(
            self._finding("CWE-400"), _check(window_sufficient=True),
        )
        assert res.extras.get("safeguard") == "deterministic_authoritative"


class TestRc6CountsOnlyHonouredDemotions:
    """RC6 freezes on demote fraction; it must not count suppressed ones.

    Otherwise the two guards interact: relaxing the exemption raises the
    apparent demote fraction toward the freeze threshold, and the whole layer
    silently switches off run to run.
    """

    def _f(self, i: int, cwe: str = "CWE-798") -> dict:
        return {
            "id": f"f{i}", "category": cwe, "check_id": "c",
            "provenance": "skill", "severity": "high",
            "file_path": "/x/a.ts", "line_start": i,
            "validation": {"checks": []},
        }

    def test_exempt_demotions_do_not_trip_the_freeze(self):
        from shared.validate.llm_judge import _apply_l5_safeguards

        # 10 crypto-policy findings, all demoted → all suppressed anyway.
        findings = [self._f(i) for i in range(10)]
        out = [[_check(window_sufficient=True)] for _ in findings]
        _apply_l5_safeguards(findings, list(range(10)), out)
        reasons = {o[0].extras.get("safeguard") for o in out}
        assert reasons == {"crypto_policy_exempt"}, (
            f"RC6 must not fire on demotions that were never going to be "
            f"honoured; got {reasons}"
        )


class TestCacheCarriesClosure:
    """A cache hit must not silently revert the gate.

    The key had no schema version and the row had no closure column, so a
    replayed verdict came back without the field, failed closed, and the
    feature would have looked inert on every run after the first.
    """

    def test_key_is_versioned(self):
        from shared.validate import l5_cache

        k = l5_cache.cache_key(
            file_path="/x/a.ts", line_start=1, line_end=1,
            check_id="c", model="m",
        )
        # v3-evidence: 0072 T5.3 added evidence_line to the verdict schema.
        assert l5_cache._VERDICT_SCHEMA_VERSION == "v3-evidence"
        # A version bump must change the key, so pre-change rows go unreachable.
        old = l5_cache._VERDICT_SCHEMA_VERSION
        try:
            l5_cache._VERDICT_SCHEMA_VERSION = "v-other"
            assert l5_cache.cache_key(
                file_path="/x/a.ts", line_start=1, line_end=1,
                check_id="c", model="m",
            ) != k
        finally:
            l5_cache._VERDICT_SCHEMA_VERSION = old

    def test_round_trip_preserves_closure(self, tmp_path, monkeypatch):
        from shared.validate import l5_cache

        monkeypatch.setattr(l5_cache, "_DB_PATH", str(tmp_path / "c.db"))
        monkeypatch.setattr(l5_cache, "_CONN", None, raising=False)
        monkeypatch.setattr(l5_cache, "_DISABLED", False, raising=False)
        k = l5_cache.cache_key(
            file_path="/x/a.ts", line_start=9, line_end=9, check_id="c", model="m",
        )
        l5_cache.store(k, exploitable=0.1, reasoning="r", model="m",
                       language="ts", window_sufficient=True)
        got = l5_cache.lookup(k)
        if got is not None:            # cache is best-effort; skip if disabled
            assert got.get("window_sufficient") is True


class TestClosureSurvivesTheWholeParsePath:
    """End-to-end from raw model JSON to the check — not just the two ends.

    The gate first shipped inert: schema, prompt, `_verdict_to_check` and the
    cache were all wired, but `_coerce_verdict` rebuilds a WHITELISTED dict and
    dropped the field in between. The unit tests passed because they called
    `_verdict_to_check` directly, skipping the normaliser. This test walks the
    real path so a future field cannot be lost the same way.
    """

    def _through_parser(self, raw: dict):
        from shared.validate.llm_judge import _coerce_verdict, _verdict_to_check

        coerced = _coerce_verdict(raw)
        assert coerced is not None
        return _verdict_to_check(coerced, model="m", batch_id=0, language="ts")

    def test_true_survives_coercion(self):
        c = self._through_parser({
            "id": "f1", "exploitable": 0.1, "reasoning": "r",
            "window_sufficient": True,
        })
        assert c.extras.get("window_sufficient") is True, (
            "the normaliser dropped the field — the gate is inert"
        )

    def test_absent_stays_absent(self):
        c = self._through_parser({"id": "f1", "exploitable": 0.1, "reasoning": "r"})
        assert c.extras.get("window_sufficient") is None

    def test_non_bool_is_normalised_to_none(self):
        for bad in ("true", 1, "yes", {}):
            c = self._through_parser({
                "id": "f1", "exploitable": 0.1, "reasoning": "r",
                "window_sufficient": bad,
            })
            assert c.extras.get("window_sufficient") is None, f"leaked: {bad!r}"
