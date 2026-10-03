"""0074 P5 (owner decision O6) — the re-anchor actuator is ON by default.

0076 shipped its quote verifier as a measurement: `VULTURE_LLM_QUOTE_VERIFY`
defaulted to `observe` and `VULTURE_LLM_QUOTE_REANCHOR` to off, so a row whose
quoted evidence sits on another line kept the model's wrong line. P3 and P4
made the move safe to take (the range fact, the per-site buckets), and O6 flips
the defaults:

  * `VULTURE_LLM_QUOTE_VERIFY`        -> `enforce`
  * `VULTURE_LLM_QUOTE_REANCHOR`      -> true
  * `VULTURE_LLM_QUOTE_DEMOTE_ABSENT` -> stays false (no demotion by default)

Rollback is RUNTIME, not a redeploy: setting `VULTURE_LLM_QUOTE_REANCHOR=false`
in the environment, with no module reload, must restore the no-move behaviour
through `_verify_and_strip` (the parse choke point) and through the dedup
survivor merge (`_adopt_line`) alike.

No new environment variable is introduced (CLAUDE.md rule 6): only the
defaults of existing switches change.

Every fixture is synthetic. No model, no network.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any

import pytest

# The absent@18 / exact@15-16 collapse fixture is 0076's; reuse it, never copy it.
from tests.unit.test_0076_enforcement import _dupe_rows

_SWITCHES = (
    "VULTURE_LLM_QUOTE_VERIFY",
    "VULTURE_LLM_QUOTE_REANCHOR",
    "VULTURE_LLM_QUOTE_DEMOTE_ABSENT",
)

# The model claims line 12; the quoted text actually lives on line 27.
_CLAIMED = 12
_TRUE_LINE = 27
_QUOTE = "const parsed = eval(userInput);"


@pytest.fixture(autouse=True)
def _bare_defaults(monkeypatch):
    """Every test starts from the SHIPPED defaults: none of the switches set."""
    for name in _SWITCHES:
        monkeypatch.delenv(name, raising=False)


def _mislocated(tmp_path) -> dict[str, Any]:
    """A finding whose quote is verbatim in the file, 15 lines from its claim."""
    src = tmp_path / "app.ts"
    body = [f"const a{i} = {i};" for i in range(40)]
    body[_TRUE_LINE - 1] = _QUOTE
    src.write_text("\n".join(body) + "\n")
    return {"file_path": str(src), "line_start": _CLAIMED, "line_end": _CLAIMED,
            "title": "eval of user input", "evidence_quote": _QUOTE}


def _verify(finding: dict[str, Any], tmp_path) -> dict[str, Any]:
    from shared.audit_runner import _verify_and_strip

    _verify_and_strip([finding], str(tmp_path))
    return finding


# ── the shipped defaults ─────────────────────────────────────────────────────


def test_bare_defaults_move_a_mislocated_row_onto_its_quote(tmp_path):
    """O6 / P5: with no switch set, VERIFY resolves to `enforce` and REANCHOR to
    true, so a row whose quote is found elsewhere in its own file is moved onto
    the verified line. Under the old defaults (observe / off) it stayed at 12."""
    finding = _verify(_mislocated(tmp_path), tmp_path)

    assert finding.get("_anchor_status") == "reanchored", (
        "the verifier must run on the bare defaults (VERIFY defaults to enforce)"
    )
    assert finding["line_start"] == _TRUE_LINE, (
        f"O6: the re-anchor actuator is ON by default; the row must move to "
        f"{_TRUE_LINE}, got {finding['line_start']}"
    )
    assert finding.get("_claimed_line") == _CLAIMED, (
        "the move must stay auditable back to the model's own claim"
    )


def test_bare_default_verify_mode_is_enforce():
    """O6: `VULTURE_LLM_QUOTE_VERIFY` resolves to `enforce` when unset."""
    from shared.audit_runner import _quote_mode

    assert _quote_mode() == "enforce"


def test_blank_verify_mode_falls_back_to_the_enforce_default(monkeypatch):
    """O6: an empty value is "unset", and resolves to the default, never to a
    hidden `observe` left behind by the old default."""
    from shared.audit_runner import _quote_mode

    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "")
    assert _quote_mode() == "enforce"


def test_bare_default_dedup_survivor_adopts_the_verified_line():
    """O6 reaches the second actuator too: the dedup survivor that adopts a
    better row's `exact` status takes that row's verified line (AC30 under the
    new default). The surviving COUNT is unchanged."""
    from shared.audit_runner import _deduplicate_findings

    out = _deduplicate_findings([], _dupe_rows(), "")
    assert len(out) == len(_dupe_rows()) - 1, "only the one duplicate collapses"
    assert (out[0]["line_start"], out[0]["line_end"]) == (15, 16), (
        "with REANCHOR on by default the survivor must take the verified line"
    )


def test_bare_default_never_demotes_an_absent_quote():
    """O6: DEMOTE_ABSENT stays OFF. An `absent` quote carries weight 0.0 on the
    defaults; the only demoting actuator is still opt-in (regression pin)."""
    from shared.anchor import anchor_weight

    assert anchor_weight("absent") == 0.0


def test_bare_default_absent_anchor_holds_no_authoritative_seat():
    """O6 / 0076 AC34: with DEMOTE_ABSENT off, the `anchor` check takes no
    authoritative seat. Asked of the voter itself (the one authority), not of
    a weight table: an `absent` anchor check must leave the verdict exactly as
    it is without one, and must not trigger the authoritative override."""
    from shared.validate.context_heuristics import _anchor_check
    from shared.validate.types import ValidationCheck
    from shared.validate.voter import _has_authoritative_demotion, vote

    anchor = _anchor_check({"_anchor_status": "absent"})
    base = [ValidationCheck(id="pattern", result="match", weight=0.4, reason="r")]

    assert not _has_authoritative_demotion([*base, anchor])
    assert vote([*base, anchor]) == vote(base), (
        "an absent quote must not move the verdict while DEMOTE_ABSENT is off"
    )


def test_feed_probe_reports_the_effective_defaults(tmp_path):
    """O6: the diagnostic env block must report what the run will actually do.
    A probe that printed REANCHOR=False while every row was being moved would
    send an operator debugging the wrong switch."""
    from shared.diag.feed_probe import render_feed

    (tmp_path / "app.py").write_text("x = 1\n")
    env = render_feed(str(tmp_path))["stats"]["env"]

    assert env["VULTURE_LLM_QUOTE_VERIFY"] == "enforce"
    assert env["VULTURE_LLM_QUOTE_REANCHOR"] is True
    assert env["VULTURE_LLM_QUOTE_DEMOTE_ABSENT"] is False


# ── runtime rollback ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("off", ["false", "0", "no", "off", "FALSE"])
def test_runtime_reanchor_false_restores_no_move(monkeypatch, tmp_path, off):
    """O6 rollback: `VULTURE_LLM_QUOTE_REANCHOR=false` set at runtime, no reload,
    restores the no-move behaviour through `_verify_and_strip`. The verifier still
    runs under the `enforce` default and still LABELS the row — only the line
    actuator is withdrawn."""
    first = _verify(_mislocated(tmp_path), tmp_path)
    assert first["line_start"] == _TRUE_LINE, "precondition: the default moves it"

    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", off)
    finding = _verify(_mislocated(tmp_path), tmp_path)

    assert finding["line_start"] == _CLAIMED, (
        f"REANCHOR={off!r} must stop the move without a reload; "
        f"got {finding['line_start']}"
    )
    assert finding.get("_anchor_status") == "reanchored", (
        "rolling the actuator back must keep the measurement (VERIFY=enforce)"
    )


def test_runtime_reanchor_false_restores_the_survivor_line(monkeypatch):
    """O6 rollback reaches the dedup survivor merge as well as the choke point."""
    from shared.audit_runner import _deduplicate_findings

    monkeypatch.setenv("VULTURE_LLM_QUOTE_REANCHOR", "false")
    out = _deduplicate_findings([], _dupe_rows(), "")
    assert out[0]["_anchor_status"] == "exact"
    assert (out[0]["line_start"], out[0]["line_end"]) == (18, 18), (
        "with REANCHOR rolled back the survivor keeps the line it was cited at"
    )


def test_explicit_observe_still_moves_nothing(monkeypatch, tmp_path):
    """Back-compat: an operator who pinned `VERIFY=observe` keeps the old
    behaviour even though REANCHOR now defaults on — `observe` never actuates."""
    monkeypatch.setenv("VULTURE_LLM_QUOTE_VERIFY", "observe")
    finding = _verify(_mislocated(tmp_path), tmp_path)
    assert finding["line_start"] == _CLAIMED


# ── the shipped deployment (docker compose) ──────────────────────────────────

_REPO = pathlib.Path(__file__).resolve().parents[4]

# The O6 code defaults, normalised. The tests above pin the CODE to this table;
# the test below pins every compose fallback to it, so the two cannot drift.
_O6_DEFAULTS = {
    "VULTURE_LLM_QUOTE_VERIFY": "enforce",
    "VULTURE_LLM_QUOTE_REANCHOR": "true",
    "VULTURE_LLM_QUOTE_DEMOTE_ABSENT": "false",
}
_BOOL_TOKENS = {**dict.fromkeys(("true", "1", "yes", "on"), "true"),
                **dict.fromkeys(("false", "0", "no", "off"), "false")}
_FALLBACK_RE = re.compile(r"\$\{(VULTURE_LLM_QUOTE_[A-Z_]+):-([^}]*)\}")


def _normalised(value: str) -> str:
    raw = value.strip().lower()
    return _BOOL_TOKENS.get(raw, raw)


def _line_fallbacks(name: str, no: int, line: str) -> list[tuple[str, int, str, str]]:
    """The quote-switch fallbacks one compose line pins."""
    return [(name, no, m[1], m[2]) for m in _FALLBACK_RE.finditer(line)
            if m[1] in _O6_DEFAULTS]


def _compose_fallbacks() -> list[tuple[str, int, str, str]]:
    """(file, line, var, fallback) for every quote switch a compose file pins."""
    out: list[tuple[str, int, str, str]] = []
    for path in sorted(_REPO.glob("docker-compose*.yml")):
        for no, line in enumerate(path.read_text().splitlines(), 1):
            out += _line_fallbacks(path.name, no, line)
    return out


def _drift(entry: tuple[str, int, str, str]) -> str:
    """A report line when the fallback disagrees with the code default, else ""."""
    name, no, var, val = entry
    if _normalised(val) == _O6_DEFAULTS[var]:
        return ""
    return f"{name}:{no} {var}={val!r} (code default {_O6_DEFAULTS[var]!r})"


def _all_drift() -> list[str]:
    """Every compose fallback that disagrees with its O6 code default."""
    return [d for d in map(_drift, _compose_fallbacks()) if d]


def test_compose_fallbacks_equal_the_o6_code_defaults():
    """O6 in the shipped deployment (Mode A/B, `docker compose up`).

    A `${VAR:-x}` fallback is not a default the code can override: compose
    always sets the variable, so every agent receives `x`. A fallback still
    reading `observe` / `false` would leave the actuator off in the default
    deployment while every code-level test above is green. Each fallback must
    equal the code default, or the compose file must stop pinning the switch."""
    assert _REPO.joinpath("docker-compose.yml").is_file(), "repo root not found"
    drift = _all_drift()
    assert not drift, "compose overrides the O6 code default:\n" + "\n".join(drift)
