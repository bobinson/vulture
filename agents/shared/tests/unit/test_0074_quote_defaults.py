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
from collections.abc import Iterator
from typing import Any

import pytest
import yaml

# The absent@18 / exact@15-16 collapse fixture is 0076's; reuse it, never copy it.
from tests.support.dupe_rows import dupe_rows as _dupe_rows
from tests.support.past_eof import QUOTE_AT_3, write_lines

# Every test starts from the SHIPPED defaults: the suite conftest removes every
# VULTURE_* variable, so none of the three quote switches is set.

# The model claims line 12; the quoted text actually lives on line 27.
_CLAIMED = 12
_TRUE_LINE = 27


def _mislocated(tmp_path) -> dict[str, Any]:
    """A finding whose quote is verbatim in the file, 15 lines from its claim."""
    body = [f"const a{i} = {i};" for i in range(40)]
    body[_TRUE_LINE - 1] = QUOTE_AT_3
    src = write_lines(tmp_path, "app.ts", body)
    return {"file_path": str(src), "line_start": _CLAIMED, "line_end": _CLAIMED,
            "title": "eval of user input", "evidence_quote": QUOTE_AT_3}


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

_VERIFY = "VULTURE_LLM_QUOTE_VERIFY"
_REANCHOR = "VULTURE_LLM_QUOTE_REANCHOR"
_DEMOTE = "VULTURE_LLM_QUOTE_DEMOTE_ABSENT"

# Which quote switches each runtime's CODE reads, keyed by the compose build
# context that ships that code. The agents read all three. The Go backend reads
# VERIFY and REANCHOR: its lineage re-anchor gate is the agent's own conjunction
# (VERIFY == enforce AND REANCHOR), so a rollback set in `.env` must reach it
# too, or the backend keeps moving lineage windows the agents no longer move.
_READERS = {
    "./agents": (_VERIFY, _REANCHOR, _DEMOTE),
    "./backend": (_VERIFY, _REANCHOR),
}


def _compose_files() -> list[pathlib.Path]:
    files = sorted(_REPO.glob("docker-compose*.yml"))
    assert _REPO.joinpath("docker-compose.yml") in files, "repo root not found"
    return files


def _split_entry(item: str) -> tuple[str, str]:
    """One list-form `NAME=value` entry as (name, value)."""
    name, _, value = item.partition("=")
    return name, value


def _env_pairs(env: list[str] | dict[str, Any]) -> Iterator[tuple[str, Any]]:
    """`environment` entries, list or mapping form, as (name, value) pairs."""
    return iter(env.items()) if isinstance(env, dict) else map(_split_entry, env)


def _env_of(service: dict[str, Any]) -> dict[str, str]:
    """A service's `environment` as {name: raw value}."""
    return {k: str(v) for k, v in _env_pairs(service.get("environment", []))}


def _build_context(service: dict[str, Any]) -> str:
    return service.get("build", {}).get("context", "")


def _pinned(env: dict[str, str]) -> Iterator[str]:
    """Each quote switch `env` forwards with anything but an empty fallback."""
    for var in (_VERIFY, _REANCHOR, _DEMOTE):
        if env.get(var, f"${{{var}:-}}") != f"${{{var}:-}}":
            yield f"{var}={env[var]!r}"


def _services() -> Iterator[tuple[str, tuple[str, ...], dict[str, str]]]:
    """(``file:service``, the quote switches its code reads, its environment)."""
    for path in _compose_files():
        doc = yaml.safe_load(path.read_text())
        for name, svc in doc["services"].items():
            yield f"{path.name}:{name}", _READERS.get(_build_context(svc), ()), _env_of(svc)


def test_compose_forwards_each_quote_switch_to_every_service_that_reads_it():
    """O6 rollback reach (#2, #26). A switch the code reads but compose never
    forwards cannot be set from `.env`: the container never sees it, so the
    runtime rollback (`VULTURE_LLM_QUOTE_REANCHOR=false`) silently stops at the
    services that lack the entry. Every reader must receive every switch."""
    missing = [f"{where} lacks {var}"
               for where, reads, env in _services() for var in set(reads) - env.keys()]
    assert not missing, "a quote-switch reader is never sent the switch:\n" + "\n".join(missing)


def test_compose_passes_the_quote_switches_through_empty():
    """O6 in the shipped deployment (Mode A/B, `docker compose up`).

    A `${VAR:-x}` fallback is a second copy of the default: compose always sets
    the variable, so every container receives `x` and the code default is never
    consulted. Both runtimes already resolve a BLANK value to their own default,
    exactly as for the eight numeric QUOTE_* knobs, so each switch is passed
    through empty (`${VAR:-}`) and the code stays the single source of truth."""
    pinned = [f"{where} {entry}" for where, _reads, env in _services() for entry in _pinned(env)]
    assert not pinned, "compose pins a copy of a quote-switch default:\n" + "\n".join(pinned)
