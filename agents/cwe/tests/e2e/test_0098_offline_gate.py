"""E2E contract: the offline gate is trustworthy (feature 0098).

``vulture-offline-skills`` decides whether a commit or a CI job may proceed, so
its verdict has to mean what it says. It must:

  1. Fail CLOSED and LOUD on a broken tool: a skill that raises is named on
     stderr and in the JSON ``errors`` list, and the run exits 2. Exit codes are
     0 = pass, 1 = blocking findings, 2 = tool or usage error.
  2. Never report a clean pass for something it did not look at: a path that
     does not exist, a directory, or a bad ``--root`` is a usage error (2);
     a file the scanner does not read (size cap, minified, extension outside
     the scan set, pruned or ignored directory, a symlink) is listed as
     ``not_scanned`` with a count on stderr.
  3. Give the verdict the full audit would give with the LLM off: the same
     redaction, the same skill-vs-skill collapse, the same deterministic
     validate stage (a ``# nosec`` waiver is ``likely_fp`` and does not block),
     and the root's own ``.gitignore`` / ``.vultureignore``.
  4. Not depend on the environment: not on ``$TMPDIR`` ancestry, not on an
     enclosing repository, and not on the order files are listed in.
  5. Leave nothing behind: the temporary copy is removed after a run, after a
     crash, and on SIGTERM / SIGHUP.
  6. Never print a secret the agent masks, nor follow a staged symlink.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

import importlib
import json
import os
import signal
import subprocess
import sys
import time
import tomllib
from pathlib import Path

import pytest

import cwe_agent
import shared
from cwe_agent import offline
from cwe_agent.offline import main
from tests._neutral import neutral_dir

COMMAND_INJECTION = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
WAIVED_INJECTION = "import os\n\n\ndef run(cmd):\n    os.system(cmd)  # nosec B605\n"
WEAK_HASH = "import hashlib\n\n\ndef digest(data):\n    return hashlib.md5(data).hexdigest()\n"
WEAK_RANDOM = "import random\n\n\ndef make_token():\n    token = random.random()\n    return token\n"
SWALLOW = "def f():\n    try:\n        g()\n    except Exception:\n        pass\n"
RAW_TOKEN = "ghp_0123456789abcdefghijABCDEFGHIJ012345"
RAW_PASSWORD = "Zx9fakeS3cretValue2024!"
SECRETS = f'DB_PASSWORD = "{RAW_PASSWORD}"\nGITHUB_TOKEN = "{RAW_TOKEN}"\n'
CLEAN = "def add(a, b):\n    return a + b\n"
INJECTION = "cwe.injection.command"
_BLOCKING_RANK = {"high": 3, "critical": 4}
_CWE_ROOT = Path(cwe_agent.__file__).resolve().parents[1]


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.fixture
def repo(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A hermetic repository: its own ``.git``, and the hook's working directory.

    Created under a neutrally named directory rather than ``tmp_path`` (named
    after the test, ``test_...``): the FULL audit classifies a file by every
    component of its absolute path, so a ``test_`` ancestor would change the
    reference verdict the parity test compares against. Not derived from
    pytest's ``--basetemp`` either, which may itself sit under ``build/`` or
    ``tests/``.
    """
    root = neutral_dir(request) / "repo"
    (root / ".git").mkdir(parents=True)
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def neutral_tmp(request: pytest.FixtureRequest) -> Path:
    """An empty, neutrally named TMPDIR for a subprocess run."""
    return neutral_dir(request)


def _env(**extra: str) -> dict[str, str]:
    paths = [str(Path(cwe_agent.__file__).resolve().parents[1]),
             str(Path(shared.__file__).resolve().parents[1])]
    current = os.environ.get("PYTHONPATH", "")
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([*paths, current] if current else paths))
    env.update(extra)
    return env


def _cli(cwd: Path, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cwe_agent.offline", *args],
        cwd=cwd, env=_env(**env), capture_output=True, text=True, timeout=300,
    )


def _json_run(capsys: pytest.CaptureFixture[str], *args: str) -> tuple[int, dict]:
    code = main(["--format", "json", *args])
    return code, json.loads(capsys.readouterr().out)


def _check_ids(rows: list[dict]) -> set[str]:
    return {r.get("check_id") for r in rows}


def _not_scanned(report: dict) -> set[str]:
    return {row["path"] for row in report["not_scanned"]}


# --- 1. exit codes and the CLI surface ---------------------------------------


def test_cli_runs_as_a_module_and_blocks_on_a_critical_finding(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    proc = _cli(repo, "src/cmd.py", TMPDIR=str(neutral_tmp))

    assert proc.returncode == 1, proc.stderr
    assert INJECTION in proc.stdout
    assert str(repo / "src" / "cmd.py") in proc.stdout


def test_cli_passes_a_clean_file_with_exit_0(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "src/add.py", CLEAN)

    proc = _cli(repo, "src/add.py", TMPDIR=str(neutral_tmp))

    assert proc.returncode == 0, proc.stderr
    assert "No blocking findings." in proc.stdout


def test_console_script_resolves_to_main() -> None:
    meta = tomllib.loads((_CWE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    target = meta["project"]["scripts"]["vulture-offline-skills"]
    module, attr = target.split(":")

    assert getattr(importlib.import_module(module), attr) is main


def test_help_documents_the_default_gate_and_exit_codes(repo: Path) -> None:
    proc = _cli(repo, "--help")

    assert proc.returncode == 0
    assert "default: high" in proc.stdout
    assert "Exit codes:" in proc.stdout
    assert "usage error" in proc.stdout


def test_no_file_argument_is_a_usage_error(repo: Path) -> None:
    assert _cli(repo).returncode == 2


# --- 2. the severity gate ------------------------------------------------------


def test_default_gate_blocks_high_but_not_medium(repo: Path, capsys) -> None:
    _write(repo, "src/med.py", WEAK_HASH)
    _write(repo, "src/tok.py", WEAK_RANDOM)

    code, report = _json_run(capsys, "src/med.py")
    assert code == 0
    assert {f["severity"] for f in report["findings"]} == {"medium"}

    code, report = _json_run(capsys, "src/tok.py")
    assert code == 1
    assert {f["severity"] for f in report["blocking"]} == {"high"}


def test_json_blocking_is_exactly_the_gated_subset(repo: Path, capsys) -> None:
    for rel, text in {"a.py": COMMAND_INJECTION, "b.py": WEAK_HASH, "c.py": WAIVED_INJECTION,
                      "d.py": WEAK_RANDOM}.items():
        _write(repo, rel, text)

    code, report = _json_run(capsys, "a.py", "b.py", "c.py", "d.py")

    gated = [
        f for f in report["findings"]
        if _BLOCKING_RANK.get(f["severity"], 0) and f.get("validation_status") != "likely_fp"
    ]
    assert code == 1
    assert report["blocking"] == gated
    assert len(gated) < len(report["findings"])


@pytest.mark.parametrize("spelling", ["CRITICAL", "Critical", "critical"])
def test_severity_is_case_insensitive(repo: Path, spelling: str) -> None:
    _write(repo, "src/tok.py", WEAK_RANDOM)
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    assert main(["--severity", spelling, "src/tok.py"]) == 0
    assert main(["--severity", spelling, "src/cmd.py"]) == 1


@pytest.mark.parametrize("bad", ["crit", "none", "off", "nonsense", ""])
def test_unknown_severity_is_a_usage_error(repo: Path, bad: str) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    with pytest.raises(SystemExit) as exc:
        main(["--severity", bad, "src/cmd.py"])

    assert exc.value.code == 2


def test_text_report_lists_the_blocking_findings_only(repo: Path, capsys) -> None:
    cmd = _write(repo, "src/cmd.py", COMMAND_INJECTION)
    med = _write(repo, "src/med.py", WEAK_HASH)

    assert main(["src/cmd.py", "src/med.py"]) == 1
    out = capsys.readouterr().out

    assert f"{cmd}:5" in out and INJECTION in out
    assert str(med) not in out
    assert "1 blocking finding(s)" in out


# --- 3. a broken skill fails closed (I1) ----------------------------------------


def _with_skill(monkeypatch: pytest.MonkeyPatch, name: str, fn) -> None:
    patched = dict(offline.SKILL_MAP)
    patched[name] = fn
    monkeypatch.setattr(offline, "SKILL_MAP", patched)


def test_a_failing_skill_is_reported_and_exits_2(repo: Path, monkeypatch, capsys) -> None:
    def _boom(_root: str) -> dict:
        raise RuntimeError("kaboom")

    _with_skill(monkeypatch, "_boom", _boom)
    _write(repo, "src/add.py", CLEAN)

    code = main(["src/add.py"])
    captured = capsys.readouterr()

    assert code == 2
    assert "Skill _boom failed: kaboom" in captured.err
    assert "No blocking findings." not in captured.out


def test_a_failing_skill_is_listed_in_json_errors(repo: Path, monkeypatch, capsys) -> None:
    def _boom(_root: str) -> dict:
        raise RecursionError("too deep")

    _with_skill(monkeypatch, "_boom", _boom)
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    code, report = _json_run(capsys, "src/cmd.py")

    assert code == 2
    assert report["errors"] == [{"skill": "_boom", "error": "too deep"}]
    assert INJECTION in _check_ids(report["blocking"])


def test_a_transient_skill_error_is_retried(repo: Path, monkeypatch) -> None:
    import errno

    calls: list[str] = []

    def _flaky(_root: str) -> dict:
        calls.append(_root)
        if len(calls) == 1:
            raise OSError(errno.EAGAIN, "try again")
        return {"findings": []}

    _with_skill(monkeypatch, "_flaky", _flaky)
    _write(repo, "src/add.py", CLEAN)

    assert main(["src/add.py"]) == 0
    assert len(calls) == 2


def test_every_skill_in_the_map_runs(repo: Path, monkeypatch) -> None:
    ran: list[str] = []

    def _spy(name: str, fn):
        def wrapped(root: str):
            ran.append(name)
            return fn(root)
        return wrapped

    spied = {name: _spy(name, fn) for name, fn in offline.SKILL_MAP.items()}
    monkeypatch.setattr(offline, "SKILL_MAP", spied)
    _write(repo, "src/add.py", CLEAN)

    main(["src/add.py"])

    assert sorted(ran) == sorted(spied)


# --- 4. nothing scanned is never a pass (I2 / I13) -----------------------------


def test_a_missing_file_is_a_usage_error(repo: Path, capsys) -> None:
    code = main(["src/typo.py"])

    assert code == 2
    assert "src/typo.py" in capsys.readouterr().err


def test_a_directory_argument_is_a_usage_error(repo: Path, capsys) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    code = main(["src"])

    assert code == 2
    assert "directory" in capsys.readouterr().err


@pytest.mark.parametrize("kind", ["missing", "file"])
def test_root_must_be_an_existing_directory(repo: Path, kind: str, capsys) -> None:
    f = _write(repo, "src/cmd.py", COMMAND_INJECTION)
    bad_root = str(repo / "nope") if kind == "missing" else str(f)

    code = main(["--root", bad_root, str(f)])
    err = capsys.readouterr().err

    assert code == 2
    assert "--root" in err


def test_files_the_scanner_does_not_read_are_reported(repo: Path, capsys) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    _write(repo, "src/big.py", COMMAND_INJECTION + "#" * (600 * 1024) + "\n")
    _write(repo, "web/app.min.js", "eval(location.hash);\n")
    (repo / "img").mkdir()
    (repo / "img" / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\0" * 64)
    _write(repo, "vendor/lib.py", COMMAND_INJECTION)
    args = ["src/cmd.py", "src/big.py", "web/app.min.js", "img/logo.png", "vendor/lib.py"]

    code = main(["--format", "json", *args])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    skipped = {str(repo / p) for p in args[1:]}
    assert _not_scanned(report) == skipped
    assert all(row["reason"] for row in report["not_scanned"])
    assert report["scanned"] == [str(repo / "src" / "cmd.py")]
    assert "4 file(s) not scanned" in captured.err
    assert "scanned 1 of 5 file(s)" in captured.err
    for path in skipped:
        assert path in captured.err
    assert code == 1
    assert {f["file_path"] for f in report["findings"]} == {str(repo / "src" / "cmd.py")}


def test_text_mode_names_the_resolved_root_on_stderr(repo: Path, monkeypatch, capsys) -> None:
    (repo / "frontend").mkdir()
    _write(repo, "frontend/add.ts", "export const a = 1;\n")
    monkeypatch.chdir(repo / "frontend")

    main(["add.ts"])
    err = capsys.readouterr().err

    assert f"root: {repo}" in err


# --- 5. staged symlinks are not followed (I4) -----------------------------------


def test_a_staged_symlink_is_not_followed(repo: Path, tmp_path: Path, capsys) -> None:
    target = _write(tmp_path, "outside/creds.py", COMMAND_INJECTION + SECRETS)
    link = repo / "src" / "settings.py"
    link.parent.mkdir(parents=True)
    link.symlink_to(target)

    code, report = _json_run(capsys, "src/settings.py")
    dump = json.dumps(report)

    assert code == 0
    assert report["findings"] == []
    assert _not_scanned(report) == {str(link)}
    assert RAW_TOKEN not in dump and RAW_PASSWORD not in dump


# --- 6. parity with the full audit (I3 / I10 / I11 / I26) ------------------------


def test_a_nosec_waiver_does_not_block(repo: Path, capsys) -> None:
    _write(repo, "src/waived.py", WAIVED_INJECTION)

    code, report = _json_run(capsys, "src/waived.py")

    hits = [f for f in report["findings"] if f.get("check_id") == INJECTION]
    assert hits and all(f["validation_status"] == "likely_fp" for f in hits)
    assert report["blocking"] == []
    assert code == 0


def test_secrets_are_masked_in_every_output(repo: Path, capsys) -> None:
    _write(repo, "src/creds.py", SECRETS)

    main(["--format", "json", "--severity", "info", "src/creds.py"])
    as_json = capsys.readouterr().out
    main(["--severity", "info", "src/creds.py"])
    as_text = capsys.readouterr()

    assert json.loads(as_json)["findings"], "the secrets fixture must produce findings"
    for out in (as_json, as_text.out, as_text.err):
        assert RAW_TOKEN not in out and RAW_PASSWORD not in out


def test_one_construct_is_one_row_after_the_skill_collapse(repo: Path, capsys) -> None:
    _write(repo, "src/tok.py", WEAK_RANDOM)

    _, report = _json_run(capsys, "--severity", "info", "src/tok.py")

    assert len([f for f in report["findings"] if f.get("line_start") == 5]) == 1


def _full_audit(root: Path) -> list[dict]:
    from shared.audit_runner import run_combined_audit

    result: list[dict] = []
    for event in run_combined_audit("parity", str(root), list(offline.SKILL_MAP),
                                    offline.SKILL_MAP, use_llm=False, validate_use_llm=False):
        for line in event.splitlines():
            if line.startswith("data:"):
                payload = json.loads(line[5:])
                if isinstance(payload.get("findings"), list):
                    result = payload["findings"]
    return result


def _shape(rows: list[dict]) -> list[tuple]:
    return sorted(
        (r.get("check_id") or "", r.get("category") or "", r.get("file_path") or "",
         r.get("line_start") or 0, r.get("severity") or "", r.get("validation_status") or "",
         r.get("code_snippet") or "")
        for r in rows
    )


def test_findings_match_the_full_audit_with_the_llm_off(repo: Path, capsys) -> None:
    files = {"src/cmd.py": COMMAND_INJECTION, "src/waived.py": WAIVED_INJECTION,
             "src/tok.py": WEAK_RANDOM, "src/creds.py": SECRETS, "src/med.py": WEAK_HASH,
             "src/swallow.py": SWALLOW}
    for rel, text in files.items():
        _write(repo, rel, text)

    _, report = _json_run(capsys, "--severity", "info", *files)

    assert report["findings"]
    assert _shape(report["findings"]) == _shape(_full_audit(repo))


def test_the_roots_ignore_files_apply_when_not_staged(repo: Path, capsys) -> None:
    _write(repo, ".vultureignore", "recorded/\n")
    _write(repo, ".gitignore", "gen/\n")
    _write(repo, "recorded/app.py", COMMAND_INJECTION)
    _write(repo, "gen/app.py", COMMAND_INJECTION)
    _write(repo, "svc.py", COMMAND_INJECTION)

    code, report = _json_run(capsys, "recorded/app.py", "gen/app.py", "svc.py")

    assert code == 1
    assert {f["file_path"] for f in report["blocking"]} == {str(repo / "svc.py")}
    assert _not_scanned(report) == {str(repo / "recorded/app.py"), str(repo / "gen/app.py")}


@pytest.mark.parametrize("where", ["outside", "nested"])
def test_a_staged_ignore_file_that_is_not_the_roots_does_not_disable_the_gate(
    repo: Path, tmp_path: Path, where: str,
) -> None:
    ignore = (_write(tmp_path, "other/.vultureignore", "*\n") if where == "outside"
              else _write(repo, "src/.vultureignore", "*\n"))
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    assert main([str(ignore), "src/cmd.py"]) == 1


# --- 7. independence from the environment (I9 / I21 / I28) ----------------------


def test_verdict_does_not_depend_on_tmpdir_ancestry(repo: Path, tmp_path: Path) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    for name in ("tests", "e2e", "fixtures"):
        tmpdir = tmp_path / name / "tmp"
        tmpdir.mkdir(parents=True)

        proc = _cli(repo, "src/cmd.py", TMPDIR=str(tmpdir))

        assert proc.returncode == 1, (name, proc.stdout, proc.stderr)
        assert INJECTION in proc.stdout


@pytest.mark.parametrize("vulnerable_first", [True, False])
def test_in_root_and_out_of_root_files_never_collide(
    repo: Path, tmp_path: Path, vulnerable_first: bool,
) -> None:
    inside = _write(repo, "_external/0/run.py", COMMAND_INJECTION)
    outside = _write(tmp_path, "elsewhere/run.py", CLEAN)
    files = [str(inside), str(outside)]

    assert main(files if vulnerable_first else files[::-1]) == 1


@pytest.mark.parametrize("vulnerable", ["inside", "outside"])
def test_an_outside_file_never_shares_a_path_with_a_root_file(
    repo: Path, tmp_path: Path, vulnerable: str, capsys,
) -> None:
    inside = _write(repo, "0/run.py", COMMAND_INJECTION if vulnerable == "inside" else CLEAN)
    outside = _write(tmp_path, "elsewhere/run.py",
                     COMMAND_INJECTION if vulnerable == "outside" else CLEAN)

    code, report = _json_run(capsys, str(inside), str(outside))

    expected = str(inside) if vulnerable == "inside" else str(outside)
    assert code == 1
    assert {f["file_path"] for f in report["blocking"]} == {expected}
    assert report["scanned"] == [str(inside), str(outside)]
    assert "vulture-offline-" not in json.dumps(report)


def test_a_symlink_listed_twice_is_reported_once(repo: Path, tmp_path: Path, capsys) -> None:
    target = _write(tmp_path, "outside/a.py", CLEAN)
    link = repo / "link.py"
    link.symlink_to(target)

    _, report = _json_run(capsys, "link.py", str(link))

    assert report["not_scanned"] == [
        {"path": str(link), "reason": report["not_scanned"][0]["reason"]},
    ]


def test_a_failing_validate_stage_is_a_tool_error(repo: Path, monkeypatch, capsys) -> None:
    def _broken(*_args, **_kwargs):
        raise RuntimeError("validate exploded")

    monkeypatch.setattr(offline, "finalize_skill_findings", _broken)
    _write(repo, "src/add.py", CLEAN)

    code, report = _json_run(capsys, "src/add.py")

    assert code == 2
    assert report["errors"] == [{"stage": "validate", "error": "validate exploded"}]


def test_a_file_listed_twice_is_scanned_once(repo: Path, capsys) -> None:
    f = _write(repo, "src/cmd.py", COMMAND_INJECTION)

    _, report = _json_run(capsys, "src/cmd.py", str(f), "./src/../src/cmd.py")

    assert report["scanned"] == [str(f)]
    assert len([x for x in report["blocking"] if x.get("check_id") == INJECTION]) == 1


# --- 8. nothing is left behind (I12 / I29) ----------------------------------------


def test_no_temporary_tree_survives_a_run(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)

    proc = _cli(repo, "src/cmd.py", TMPDIR=str(neutral_tmp))

    assert proc.returncode == 1
    assert list(neutral_tmp.iterdir()) == []


_SLOW_RUNNER = """\
import sys, time
from cwe_agent import offline

def _slow(_root):
    time.sleep(120)
    return {"findings": []}

offline.SKILL_MAP = {"slow": _slow}
sys.exit(offline.main(sys.argv[1:]))
"""


@pytest.mark.parametrize("signum", [signal.SIGTERM, signal.SIGHUP])
def test_a_terminated_run_removes_its_temporary_tree(
    repo: Path, neutral_tmp: Path, tmp_path: Path, signum: int,
) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    runner = _write(tmp_path, "slow_runner.py", _SLOW_RUNNER)
    proc = subprocess.Popen(
        [sys.executable, str(runner), "src/cmd.py"], cwd=repo,
        env=_env(TMPDIR=str(neutral_tmp)), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 60
    while not list(neutral_tmp.iterdir()) and time.monotonic() < deadline:
        time.sleep(0.05)
    assert list(neutral_tmp.iterdir()), "the run never created its temporary tree"
    time.sleep(0.5)

    proc.send_signal(signum)
    proc.communicate(timeout=60)

    assert proc.returncode == 128 + signum
    assert list(neutral_tmp.iterdir()) == []


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a mode-000 file")
def test_an_unreadable_file_is_a_tool_error_and_leaves_nothing(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    locked = _write(repo, "src/locked.py", CLEAN)
    locked.chmod(0)
    try:
        proc = _cli(repo, "src/cmd.py", "src/locked.py", TMPDIR=str(neutral_tmp))
    finally:
        locked.chmod(0o644)

    assert proc.returncode == 2
    assert "src/locked.py" in proc.stderr
    assert "Traceback" not in proc.stderr
    assert list(neutral_tmp.iterdir()) == []


def test_a_file_over_every_read_cap_is_reported_not_copied(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    _write(repo, "src/huge.py", COMMAND_INJECTION + "#" * 4096 + "\n")

    proc = _cli(repo, "--format", "json", "src/cmd.py", "src/huge.py", TMPDIR=str(neutral_tmp),
                VULTURE_MAX_FILE_SIZE="2048", VULTURE_MAX_MANIFEST_SIZE="2048")
    report = json.loads(proc.stdout)

    rows = {row["path"]: row["reason"] for row in report["not_scanned"]}
    assert set(rows) == {str(repo / "src" / "huge.py")}
    assert "not copied" in rows[str(repo / "src" / "huge.py")]
    assert proc.returncode == 1


# --- 9. what a verdict covers, and what it may print ---------------------------

CLEARTEXT = f'DB_PASSWORD = "{RAW_PASSWORD}"\n'
CLEARTEXT_CHECK = "cwe.info_exposure.cleartext_storage"
TWO_SINKS = (
    "import os, subprocess\n"
    "def run(cmd):\n"
    "    subprocess.call(cmd, shell=True)\n"
    '    os.system("ls " + cmd)\n'
)
FOLDER_OPEN_TASK = json.dumps({
    "version": "2.0.0",
    "tasks": [{"label": "setup", "type": "shell", "command": "./scripts/bootstrap.sh",
               "runOptions": {"runOn": "folderOpen"}}],
})


@pytest.mark.parametrize("name", ["docs", "example-runner", "exampleco", "testbed"])
def test_verdict_does_not_depend_on_a_tmpdir_named_like_a_suppression_glob(
    repo: Path, neutral_tmp: Path, name: str,
) -> None:
    """The skills' own suppression globs (``*/docs/*``, ``*/example*``) match the
    ABSOLUTE path, so a TMPDIR under such a directory must not silence them.

    Under ``neutral_tmp``, not ``tmp_path``: pytest names ``tmp_path`` after the
    test (``test_...``), which would make the base non-neutral for another reason.
    """
    _write(repo, "app/settings.py", CLEARTEXT)
    tmpdir = neutral_tmp / name / "t"
    tmpdir.mkdir(parents=True)

    proc = _cli(repo, "--severity", "medium", "app/settings.py", TMPDIR=str(tmpdir))

    assert proc.returncode == 1, (name, proc.stdout, proc.stderr)
    assert CLEARTEXT_CHECK in proc.stdout


@pytest.mark.parametrize("rel", ["web/app.min.js", "vendor/app.py"])
def test_nothing_scanned_is_never_reported_as_a_clean_pass(repo: Path, rel: str, capsys) -> None:
    _write(repo, rel, COMMAND_INJECTION)

    code = main([rel])
    out = capsys.readouterr().out

    assert code == 0
    assert "No blocking findings." not in out
    assert "0 of 1 file(s) scanned" in out


@pytest.mark.parametrize("kind", ["initialised", "uninitialised"])
def test_a_submodule_path_is_reported_not_refused(repo: Path, kind: str, capsys) -> None:
    """``git diff --name-only`` lists a submodule bump as the submodule's path."""
    lib = repo / "lib"
    lib.mkdir()
    if kind == "initialised":
        (lib / ".git").write_text("gitdir: ../.git/modules/lib\n", encoding="utf-8")
        _write(lib, "inner.py", COMMAND_INJECTION)
    else:
        _write(repo, ".gitmodules", '[submodule "lib"]\n\tpath = lib\n\turl = ../lib.git\n')
    _write(repo, "app.py", COMMAND_INJECTION)

    code, report = _json_run(capsys, "app.py", "lib")

    assert code == 1
    assert _not_scanned(report) == {str(lib)}
    assert "submodule" in report["not_scanned"][0]["reason"]
    assert {f["file_path"] for f in report["blocking"]} == {str(repo / "app.py")}


@pytest.mark.parametrize(("rel", "text", "raw"), [
    ("notes.md", f'token {RAW_TOKEN}\npassword = "hunter2hunter2"\n', RAW_TOKEN),
    ("src/run.py", f"# deploy token {RAW_TOKEN}\n" + COMMAND_INJECTION, RAW_TOKEN),
    ("package.json",
     '{ "name": "x", "version": "1.0.0", "dependencies": '
     '{ "lib": "git+https://deploy:Pw4ndR0ckz99zz@github.com/org/lib.git" } }\n',
     "Pw4ndR0ckz99zz"),
    ("requirements.txt",
     "--extra-index-url https://user:Hunter2Secret99@pypi.example.com/simple\nflask==2.0.0\n",
     "Hunter2Secret99"),
    ("src/app.js",
     f'const token = "{RAW_TOKEN}";\nlocalStorage.setItem("pw", "{RAW_PASSWORD}");\n'
     'fetch("http://x.example.com/?api_key=Pw4ndR0ckz99abc");\n',
     RAW_PASSWORD),
    ("src/app2.js",
     'fetch("http://x.example.com/?api_key=Pw4ndR0ckz99abc");\n', "Pw4ndR0ckz99abc"),
])
def test_a_secret_never_leaks_through_a_neighbouring_finding(
    repo: Path, rel: str, text: str, raw: str, capsys,
) -> None:
    _write(repo, rel, text)

    _, report = _json_run(capsys, "--severity", "info", rel)

    assert report["findings"], "the fixture must produce findings"
    assert raw not in json.dumps(report)


def test_an_outside_file_keeps_its_autorun_directory_and_is_named(
    repo: Path, tmp_path: Path, capsys,
) -> None:
    task = _write(repo, ".vscode/tasks.json", FOLDER_OPEN_TASK)
    other = tmp_path / "other"
    other.mkdir()

    code = main(["--root", str(other), str(task)])
    captured = capsys.readouterr()

    assert code == 1
    assert "cwe.workspace_autorun.vscode_task" in captured.out
    assert f"{task}" in captured.err and "outside the root" in captured.err


def test_a_closed_stdout_is_a_tool_error_not_a_block(repo: Path, neutral_tmp: Path) -> None:
    for i in range(60):
        _write(repo, f"src/m{i}.py", SWALLOW)
    files = [f"src/m{i}.py" for i in range(60)]
    proc = subprocess.Popen(
        [sys.executable, "-m", "cwe_agent.offline", "--format", "json", "--severity",
         "critical", *files],
        cwd=repo, env=_env(TMPDIR=str(neutral_tmp)),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None and proc.stderr is not None
    proc.stdout.read(100)
    proc.stdout.close()
    err = proc.stderr.read().decode()
    proc.wait(timeout=300)

    assert proc.returncode == 2, err
    assert "Traceback" not in err


def test_a_failing_validate_stage_prints_no_internal_rows(repo: Path, monkeypatch, capsys) -> None:
    import shared.validate

    def _broken(*_args, **_kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(shared.validate, "validate", _broken)
    _write(repo, "src/creds.py", SECRETS)

    code, report = _json_run(capsys, "--severity", "info", "src/creds.py")

    assert code == 2
    assert report["errors"] == [{"stage": "validate", "error": "boom"}]
    assert not [k for f in report["findings"] for k in f if k.startswith("_")]
    assert RAW_TOKEN not in json.dumps(report)


def test_a_rollup_parent_never_counts_as_a_blocking_finding(repo: Path, capsys) -> None:
    _write(repo, "src/run.py", TWO_SINKS)

    code = main(["src/run.py"])
    out = capsys.readouterr().out
    _, report = _json_run(capsys, "src/run.py")

    assert code == 1
    assert "[None]" not in out
    assert "2 blocking finding(s)" in out
    assert len(report["blocking"]) == 2
    assert all(f.get("check_id") for f in report["blocking"])


def test_json_mode_names_the_resolved_root_on_stderr(repo: Path, capsys) -> None:
    _write(repo, "src/add.py", CLEAN)

    main(["--format", "json", "src/add.py"])

    assert f"root: {repo}" in capsys.readouterr().err
