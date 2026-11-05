"""E2E: a finding that cites the scan root leaves the agent citing ``"."``.

The backend canonicalises every finding path against the scan root, and the
root itself becomes ``"."``. A row that left the agent carrying the absolute
root instead was keyed on the HOST path by everything upstream of that
canonicaliser -- the v1 fingerprint, the scan-report archive, the window stage
(which tried to read a directory) and the path classifier (which judged the
directories above the repository). The repository-wide skills now emit ``"."``
themselves; this pins the backstop at the pre-egress choke point that both
tiers pass, so a skill or a model row that still cites the root cannot bring
the host path back, and pins that the agent's own dedup treats the two
spellings as one path.

The model is never called: one batch's call is replaced by a script, so the
real batch loop, final dedup and emit path run. All fixtures are synthetic.
"""

from __future__ import annotations

from pathlib import Path

from shared import audit_runner
from tests.support.agent_run import result_payload

REPO_CHECK = "demo.repo.no_policy"
OTHER_REPO_CHECK = "demo.repo.no_owners"
FILE_CHECK = "demo.file.weak"


def _repo_row(file_path: str, line: int = 0, check_id: str = REPO_CHECK) -> dict:
    return {
        "severity": "medium", "category": "policy", "title": f"Repository lacks {check_id}",
        "description": "the repository carries no policy", "file_path": file_path,
        "line_start": line, "line_end": line, "recommendation": "add one",
        "check_id": check_id,
    }


def _file_row(file_path: str) -> dict:
    return {
        "severity": "high", "category": "policy", "title": "Weak setting",
        "description": "a weak setting", "file_path": file_path,
        "line_start": 1, "line_end": 1, "recommendation": "harden it",
        "check_id": FILE_CHECK,
    }


def _tree(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for i in range(3):
        (root / f"m{i}.py").write_text(f"# module {i}\n" + ("value = 1\n" * 20))
    return root


def _run(root: Path, skill, use_llm: bool) -> list[dict]:
    return result_payload(list(audit_runner.run_combined_audit(
        run_id="repo-root-path", source_path=str(root), categories=["policy"],
        skill_map={"policy": skill}, skill_tools=["tool"], instructions="inst",
        use_llm=use_llm,
    )))["findings"]


def _scripted_llm(monkeypatch, rows: list[dict]) -> None:
    """A hermetic LLM-on run whose one batch answers ``rows``; no network."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-no-network")
    monkeypatch.setenv("VULTURE_LLM_MODEL", "gpt-4o")
    monkeypatch.setattr(audit_runner, "_preflight_vetoes", lambda *a, **k: (False, ""))
    answered = []

    async def one_batch(*args, **kwargs):
        if answered:
            return [], None, 10, 10
        answered.append(True)
        return [dict(r) for r in rows], None, 10, 10

    monkeypatch.setattr(audit_runner, "_collect_llm_findings_async", one_batch)


def test_a_skill_row_citing_the_root_leaves_as_the_root_token(tmp_path) -> None:
    root = _tree(tmp_path)

    def skill(source_path: str) -> dict:
        return {"findings": [
            _repo_row(source_path), _repo_row(source_path + "/", 1, OTHER_REPO_CHECK),
            _file_row(f"{source_path}/m0.py"),
        ]}

    cited = {f.get("check_id"): f["file_path"] for f in _run(root, skill, use_llm=False)}
    assert cited == {
        REPO_CHECK: ".", OTHER_REPO_CHECK: ".", FILE_CHECK: str(root / "m0.py"),
    }


def test_a_sibling_that_shares_the_roots_prefix_is_not_the_root(tmp_path) -> None:
    """``/x/repo-old`` is not ``/x/repo``: only the root itself becomes ``"."``."""
    root = _tree(tmp_path / "repo")
    sibling = str(tmp_path / "repo-old")

    def skill(_source_path: str) -> dict:
        return {"findings": [_repo_row(sibling)]}

    assert [f["file_path"] for f in _run(root, skill, use_llm=False)] == [sibling]


def test_a_model_row_citing_the_root_leaves_as_the_root_token(tmp_path, monkeypatch) -> None:
    root = _tree(tmp_path)
    model_row = _repo_row(str(root), 1)
    model_row.update(check_id="", title="Repository has no incident process")
    _scripted_llm(monkeypatch, [model_row])

    findings = _run(root, lambda _p: {"findings": []}, use_llm=True)
    cited = [f for f in findings if f["title"] == model_row["title"]]
    assert [f["file_path"] for f in cited] == ["."]


def test_a_model_row_naming_no_file_collapses_into_the_skill_row(tmp_path, monkeypatch) -> None:
    """An empty ``file_path`` and ``"."`` both mean the repository as a whole."""
    root = _tree(tmp_path)
    _scripted_llm(monkeypatch, [_repo_row("", 0)])

    findings = _run(root, lambda _p: {"findings": [_repo_row(".")]}, use_llm=True)
    repo = [f for f in findings if f.get("check_id") == REPO_CHECK]
    assert [(f["file_path"], f["provenance"]) for f in repo] == [(".", "skill")]


def test_a_model_row_citing_the_root_collapses_into_the_skill_row(tmp_path, monkeypatch) -> None:
    """The skill says ``"."`` and the model says ``/abs/root`` for the same
    check: one finding, not two. The agent's dedup key must spell the root the
    way the skill now does."""
    root = _tree(tmp_path)
    _scripted_llm(monkeypatch, [_repo_row(str(root), 1)])

    findings = _run(root, lambda _p: {"findings": [_repo_row(".")]}, use_llm=True)
    repo = [f for f in findings if f.get("check_id") == REPO_CHECK]
    assert len(repo) == 1, [(f["file_path"], f.get("provenance")) for f in repo]
    assert repo[0]["file_path"] == "."
    assert repo[0]["provenance"] == "skill"
