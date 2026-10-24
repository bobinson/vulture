"""E2E contract: the offline gate's residual edges (feature 0098).

``vulture-offline-skills`` decides whether a commit or a CI job may proceed. On
top of the contract in ``test_0098_offline_gate.py`` it must:

  1. Never print a private key's body, nor garble a row, through ANY finding's
     code window, including a neighbouring finding's.
  2. Treat a directory argument as a submodule only when git would: it holds a
     ``.git`` entry, or the superproject's ``.gitmodules`` declares it. An
     empty plain directory is a usage error (exit 2).
  3. Refuse to pass silently when the working directory sits inside a
     directory an audit of the discovered root prunes (``build/``): exit 2,
     with the reason and the ``--root`` way out.
  4. Leave no temporary tree behind after a NORMAL run.
  5. Document an install that never resolves a first-party package from an
     index, and the catalog tier's per-CWE cap.
  6. Never copy content no reader takes, report the true reason a file was not
     scanned, and still block a served sensitive file over every read cap.
  7. Escape control, bidi and surrogate characters in everything printed as
     text, including argparse's own messages.
  8. Exit 2, before scanning, when stdout is closed.

These tests are the business contract. Do NOT weaken them to make code pass.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

import cwe_agent
import shared
from cwe_agent import offline
from cwe_agent.offline import main
from shared.tools.file_scanner import MAX_FILE_SIZE, MAX_MANIFEST_SIZE
from tests._neutral import neutral_dir

COMMAND_INJECTION = "import os\n\n\ndef run(cmd):\n    os.system(cmd)\n"
CLEAN = "def add(a, b):\n    return a + b\n"
BEGIN = "-----" + "BEGIN"
END = "-----" + "END"
KEY_BODY = "MIIEowIBAAKCAQEA" + "q7ZbX9sk1Vd0Lw3HfYtRmN4pCo2eYvU8" + "Jg5TzKcW6hQiBxAo"
PEM_SOURCE = (
    "import os\n"
    f'KEY = """{BEGIN} RSA PRIVATE KEY-----\n'
    f"{KEY_BODY}\n"
    f'{END} RSA PRIVATE KEY-----"""\n'
    "os.system(input())\n"
)
GARBLED = '"***REDACTED***""***REDACTED***'
_REPO_ROOT = Path(cwe_agent.__file__).resolve().parents[3]
GUIDE = _REPO_ROOT / "docs" / "guides" / "offline_skills_gate.md"


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


@pytest.fixture
def repo(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A hermetic repository (its own ``.git``) that is the working directory."""
    root = neutral_dir(request) / "repo"
    (root / ".git").mkdir(parents=True)
    monkeypatch.chdir(root)
    return root


@pytest.fixture
def neutral_tmp(request: pytest.FixtureRequest) -> Path:
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


# --- 1. a key body never leaks through a window ------------------------------


def test_a_private_key_body_never_leaks_through_a_neighbouring_window(repo: Path, capsys) -> None:
    _write(repo, "app/pem.py", PEM_SOURCE)

    code, report = _json_run(capsys, "--severity", "info", "app/pem.py")
    windows = [str(f.get("code_snippet")) for f in report["findings"]]

    assert code == 1
    assert "cwe.injection.command" in {f.get("check_id") for f in report["findings"]}
    assert KEY_BODY[:24] not in json.dumps(report)
    assert not [w for w in windows if GARBLED in w]


# --- 7. nothing printed as text can steer a terminal ----------------------------

_RAW_CONTROLS = ("\x1b", "\x07", "\r", "\u202e", "\u200e")


def _has_raw_control(text: str) -> bool:
    return any(c in text for c in _RAW_CONTROLS)


def test_control_characters_in_a_file_name_are_escaped_in_text_output(repo: Path, capsys) -> None:
    name = "mw\x1b[2K\rok.py"
    _write(repo, name, COMMAND_INJECTION)

    code = main([name])
    out, err = capsys.readouterr()

    assert code == 1
    assert not _has_raw_control(out) and not _has_raw_control(err)
    assert "mw\\x1b[2K\\rok.py" in out


def test_a_bidi_mark_in_a_file_name_is_escaped(repo: Path, capsys) -> None:
    name = "lrm\u200eb.py"
    _write(repo, name, COMMAND_INJECTION)

    code = main([name])
    out, err = capsys.readouterr()

    assert code == 1
    assert "\u200e" not in out and "\u200e" not in err
    assert "lrm\\u200eb.py" in out


def test_control_characters_in_a_bad_argument_are_escaped(repo: Path, capsys) -> None:
    code = main(["no\x1b]0;pwned\x07such.py"])
    err = capsys.readouterr().err

    assert code == 2
    assert not _has_raw_control(err)
    assert "no\\x1b]0;pwned\\x07such.py" in err


def test_control_characters_in_an_unknown_option_are_escaped(repo: Path, neutral_tmp: Path) -> None:
    """argparse prints its own usage error; it must not carry a raw escape either."""
    _write(repo, "a.py", CLEAN)

    proc = _cli(repo, "--\x1b]0;x\x07y", "a.py", TMPDIR=str(neutral_tmp))

    assert proc.returncode == 2
    assert "\x1b" not in proc.stderr and "\x07" not in proc.stderr
    assert "\\x1b]0;x\\x07y" in proc.stderr


def test_json_output_escapes_control_characters(repo: Path, capsys) -> None:
    name = "mw\x1b[2K\rok.py"
    _write(repo, name, COMMAND_INJECTION)

    code = main(["--format", "json", name])
    out = capsys.readouterr().out

    assert code == 1
    assert not _has_raw_control(out)
    assert json.loads(out)["blocking"][0]["file_path"].endswith(name)


# --- 8. a closed stdout is a tool error, found before scanning ------------------


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh to close fd 1")
def test_a_fully_closed_stdout_is_a_tool_error(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "clean.py", CLEAN)

    proc = subprocess.run(
        ["/bin/sh", "-c", f'exec "{sys.executable}" -m cwe_agent.offline clean.py >&-'],
        cwd=repo, env=_env(TMPDIR=str(neutral_tmp)), capture_output=True, text=True,
        timeout=300,
    )

    assert proc.returncode == 2, proc.stderr
    assert "Traceback" not in proc.stderr
    assert "cannot write the report" in proc.stderr
    assert list(neutral_tmp.iterdir()) == []


# --- 6. content no reader takes is never copied; the reason is the true one ------

SERVED_SENSITIVE = "cwe.info_exposure.served_sensitive_file"


def _sparse(path: Path, size: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        fh.truncate(size)
    return path


def _reasons(report: dict) -> dict[str, str]:
    return {row["path"]: row["reason"] for row in report["not_scanned"]}


def test_a_file_outside_the_scan_set_reports_its_extension_not_its_size(
    repo: Path, capsys,
) -> None:
    """The extension is WHY no reader takes it; being over the read cap as well
    is reported after it, never instead of it."""
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    _sparse(repo / "assets" / "blob.bin", 3 * 1024 * 1024)
    _write(repo, "assets/small.bin", "x")

    code, report = _json_run(capsys, "src/cmd.py", "assets/blob.bin", "assets/small.bin")
    reasons = _reasons(report)

    assert code == 1
    assert reasons[str(repo / "assets" / "blob.bin")].split("; ")[0] == (
        "extension outside the scan set")
    assert reasons[str(repo / "assets" / "small.bin")] == "extension outside the scan set"


def test_content_no_reader_takes_is_never_copied(repo: Path, monkeypatch, capsys) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    blob = _sparse(repo / "assets" / "blob.bin", 3 * 1024 * 1024)
    big = _write(repo, "src/big.py", COMMAND_INJECTION + "#" * (MAX_FILE_SIZE + 1) + "\n")
    copied: list[Path] = []
    real_copy = offline._copy

    def _spy(src: Path, dst: Path) -> None:
        copied.append(src)
        real_copy(src, dst)

    monkeypatch.setattr(offline, "_copy", _spy)

    code, report = _json_run(capsys, "src/cmd.py", "assets/blob.bin", "src/big.py")

    assert code == 1
    assert blob not in copied and big not in copied
    assert repo / "src" / "cmd.py" in copied
    assert {str(blob), str(big)} <= set(_reasons(report))


def test_a_served_sensitive_file_over_every_read_cap_still_blocks(repo: Path, capsys) -> None:
    """A name-only check needs the NAME, not the content: the full audit flags a
    served database however large it is, so the gate must too."""
    _sparse(repo / "public" / "huge.sqlite", MAX_MANIFEST_SIZE + 1024 * 1024)

    code, report = _json_run(capsys, "public/huge.sqlite")

    assert code == 1
    assert SERVED_SENSITIVE in {f.get("check_id") for f in report["blocking"]}


def test_a_served_sensitive_file_outside_the_scan_set_still_blocks(repo: Path, capsys) -> None:
    _sparse(repo / "public" / "mid.sqlite", 1024 * 1024)

    code, report = _json_run(capsys, "public/mid.sqlite")

    assert code == 1
    assert SERVED_SENSITIVE in {f.get("check_id") for f in report["blocking"]}


def test_a_stand_in_never_exceeds_the_read_cap_plus_one(repo: Path, monkeypatch, capsys) -> None:
    """However large the original, at most the read cap plus one byte is staged."""
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    _sparse(repo / "src" / "giant.py", 2 * 1024 ** 3)
    staged: dict[str, int] = {}
    real_scan = offline._scan_tree

    def _spy(tree, result) -> None:
        staged.update({src.name: dst.stat().st_size for dst, src in tree.copies.items()})
        real_scan(tree, result)

    monkeypatch.setattr(offline, "_scan_tree", _spy)

    code, _ = _json_run(capsys, "src/cmd.py", "src/giant.py")

    assert code == 1
    assert staged["giant.py"] == MAX_FILE_SIZE + 1


# --- 3. a working directory inside a pruned directory never passes silently -----


@pytest.fixture
def pruned_project(request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch) -> Path:
    """``outer/.git`` with the project at ``outer/build/proj``, run from the project."""
    outer = neutral_dir(request) / "outer"
    (outer / ".git").mkdir(parents=True)
    proj = outer / "build" / "proj"
    _write(proj, "app/a.py", COMMAND_INJECTION)
    monkeypatch.chdir(proj)
    return proj


def test_a_working_directory_inside_a_pruned_directory_is_a_usage_error(
    pruned_project: Path, capsys,
) -> None:
    code = main(["--format", "json", "app/a.py"])
    captured = capsys.readouterr()
    report = json.loads(captured.out)

    assert code == 2
    assert [e.get("stage") for e in report["errors"]] == ["root"]
    assert "build" in captured.err and "--root" in captured.err


def test_an_explicit_root_inside_a_pruned_directory_is_gated(pruned_project: Path, capsys) -> None:
    code, report = _json_run(capsys, "--root", ".", "app/a.py")

    assert code == 1
    assert report["errors"] == []


def test_a_mixed_set_under_a_pruned_cwd_still_gives_a_verdict(pruned_project: Path, capsys) -> None:
    """Only a run where EVERY in-root file is under the pruned directory is refused."""
    _write(pruned_project.parents[1], "src/b.py", COMMAND_INJECTION)

    code, report = _json_run(capsys, "app/a.py", "../../src/b.py")

    assert code == 1
    assert report["errors"] == []
    assert str(pruned_project / "app" / "a.py") in {r["path"] for r in report["not_scanned"]}


# --- 4. a normal run leaves nothing behind -------------------------------------


@pytest.mark.parametrize(("text", "expected"), [(COMMAND_INJECTION, 1), (CLEAN, 0)],
                         ids=["blocked", "pass"])
def test_a_normal_run_leaves_no_temporary_tree(
    repo: Path, monkeypatch, capsys, text: str, expected: int,
) -> None:
    _write(repo, "src/app.py", text)
    made: list[Path] = []
    real = offline._neutral_temp

    def _spy() -> Path:
        made.append(real())
        return made[-1]

    monkeypatch.setattr(offline, "_neutral_temp", _spy)

    code = main(["src/app.py"])
    capsys.readouterr()

    assert code == expected
    assert made, "the run never made its temporary tree"
    assert not [p for p in made if p.exists()]


def test_a_normal_run_leaves_tmpdir_empty(repo: Path, neutral_tmp: Path) -> None:
    _write(repo, "src/app.py", CLEAN)

    proc = _cli(repo, "src/app.py", TMPDIR=str(neutral_tmp))

    assert proc.returncode == 0, proc.stderr
    assert list(neutral_tmp.iterdir()) == []


# --- 2. only a real submodule is reported rather than refused ---------------------


def _declare(superproject: Path, rel: str) -> None:
    _write(superproject, ".gitmodules",
           f'[submodule "{rel}"]\n\tpath = {rel}\n\turl = ../{Path(rel).name}.git\n')


def test_an_empty_directory_that_is_not_a_submodule_is_a_usage_error(repo: Path, capsys) -> None:
    (repo / "lib").mkdir()
    _write(repo, "app.py", COMMAND_INJECTION)

    code = main(["app.py", "lib"])
    err = capsys.readouterr().err

    assert code == 2
    assert "is a directory" in err


def test_an_empty_directory_declared_in_gitmodules_is_reported(repo: Path, capsys) -> None:
    (repo / "lib").mkdir()
    _declare(repo, "lib")
    _write(repo, "app.py", COMMAND_INJECTION)

    code, report = _json_run(capsys, "app.py", "lib")

    assert code == 1
    assert {r["path"] for r in report["not_scanned"]} == {str(repo / "lib")}
    assert "submodule" in report["not_scanned"][0]["reason"]


def test_a_declared_submodule_in_a_subdirectory_is_reported(
    repo: Path, monkeypatch, capsys,
) -> None:
    (repo / "third_party" / "lib").mkdir(parents=True)
    _declare(repo, "third_party/lib")
    _write(repo, "src/app.py", COMMAND_INJECTION)
    monkeypatch.chdir(repo / "src")

    code, report = _json_run(capsys, "app.py", "../third_party/lib")

    assert code == 1
    assert {r["path"] for r in report["not_scanned"]} == {str(repo / "third_party" / "lib")}
    assert "submodule" in report["not_scanned"][0]["reason"]


# --- 5. the guide: a pinned, first-party-local install; the catalog cap ----------

_FENCE = re.compile(r"^```[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)
_INLINE = re.compile(r"`([^`\n]+)`")
_FIRST_PARTY = re.compile(r"(?:agents/)?(?:shared|cwe)/?(?=[\s\"']|$)")
_LOCKFILE = _REPO_ROOT / "agents" / "requirements-frozen.txt"


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _blocks(text: str) -> list[str]:
    return [m.group(1) for m in _FENCE.finditer(text)]


def _inline_spans(text: str) -> list[str]:
    return _INLINE.findall(_FENCE.sub("", text))


def _first_party_installs(chunk: str) -> list[str]:
    return [line for line in chunk.splitlines()
            if "pip install" in line and _FIRST_PARTY.search(line.split("pip install", 1)[1])]


def test_the_documented_install_never_resolves_first_party_packages_from_an_index() -> None:
    """``vulture-shared`` is not on any index, so an install that lets pip
    resolve it there installs whatever squats the name. Every documented
    install of a first-party package is ``--no-deps``, third-party packages come
    from the hashed lockfile first, and every clone is pinned to a ref."""
    text = _guide()
    chunks = _blocks(text) + _inline_spans(text)
    installs = [line for chunk in chunks for line in _first_party_installs(chunk)]

    assert installs, "the guide documents no install"
    assert [line for line in installs if "--no-deps" not in line] == []
    for block in _blocks(text):
        first = next((i for i, line in enumerate(block.splitlines())
                      if line in _first_party_installs(block)), None)
        if first is None:
            continue
        before = "\n".join(block.splitlines()[:first])
        assert "--require-hashes" in before and "requirements-frozen.txt" in before, block
    for block in _blocks(text):
        for i, line in enumerate(block.splitlines()):
            if "git clone" in line:
                rest = "\n".join(block.splitlines()[i:])
                assert "--branch" in line or " checkout " in rest, line


def test_the_guide_documents_the_pythonpath_form() -> None:
    text = _guide()

    assert "PYTHONPATH=" in text
    assert "-m cwe_agent.offline" in text
    assert "--require-hashes -r" in text


def _requirement_names(pyproject: Path) -> set[str]:
    deps = tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["dependencies"]
    names = {re.split(r"[\[<>=!~ ;]", d, maxsplit=1)[0] for d in deps}
    return {re.sub(r"[-_.]+", "-", n).lower() for n in names if not n.startswith("vulture-")}


def test_the_lockfile_pins_every_third_party_dependency_of_the_gate() -> None:
    agents = _REPO_ROOT / "agents"
    wanted = _requirement_names(agents / "shared" / "pyproject.toml") | _requirement_names(
        agents / "cwe" / "pyproject.toml")
    pinned = {re.sub(r"[-_.]+", "-", m.group(1)).lower()
              for m in re.finditer(r"^([A-Za-z0-9][\w.\-]*)==\S+ \\$",
                                   _LOCKFILE.read_text(encoding="utf-8"), re.MULTILINE)}

    assert wanted and wanted <= pinned, wanted - pinned


def test_the_guide_states_the_catalog_cap() -> None:
    from cwe_agent.skills.catalog_detector import _MAX_FILES_PER_CWE

    assert f"{_MAX_FILES_PER_CWE} files per CWE per scanned tree" in _guide()


# --- 9. a secret on a neighbouring line never leaks, whatever its form ----------
#
# A finding's window spans several rows. A row that a secret finding cites is
# masked in every window whatever CWE the secret skill gave it, a secret next to
# a triple quote is masked like any other, and a credential-NAMED hex value or a
# provider token is masked even when no secret finding cites its row.

PASSWORD = "S3cretPassw0rd" + "XYZ"
HEX = "9f8e7d6c5b4a3928" + "1706f5e4d3c2b1a0"


def test_a_secret_scan_row_masks_its_line_in_every_window_whatever_its_cwe(
    repo: Path, capsys,
) -> None:
    """``password_in_config_file`` is CWE-260 and ``env_var_cleartext_secret``
    CWE-526: the neighbouring configuration findings must not print the row."""
    _write(repo, "config/app.yaml",
           f"server:\n  debug: true\n  password: {PASSWORD}\n  ssl_verify: false\n")
    _write(repo, "docker-compose.yml",
           "services:\n  web:\n    image: nginx\n    environment:\n"
           f"      - DB_PASSWORD={PASSWORD}\n    command: sh -c \"debug=true\"\n")

    _, report = _json_run(capsys, "--severity", "info", "config/app.yaml", "docker-compose.yml")
    checks = {str(f.get("check_id")) for f in report["findings"]}

    assert {c for c in checks if c.startswith("cwe.secret_scan.")}
    assert checks - {c for c in checks if c.startswith("cwe.secret_scan.")}
    assert PASSWORD not in json.dumps(report)


TRIPLE_QUOTED = {
    "db.py": ('import os\nimport psycopg2\nconn = psycopg2.connect(host="db", password="'
              + PASSWORD + '", options="""-c search_path=app""")\nos.system(input())\n'),
    "cfg.py": ('import os\nDB_PASSWORD = "' + PASSWORD
               + '"  # rotated, see """ops runbook"""\nos.system(input())\n'),
}


def test_a_secret_beside_a_triple_quote_never_leaks(repo: Path, capsys) -> None:
    for name, text in TRIPLE_QUOTED.items():
        _write(repo, f"app/{name}", text)

    _, report = _json_run(capsys, "--severity", "info", "app/db.py", "app/cfg.py")

    assert "cwe.injection.command" in {f.get("check_id") for f in report["findings"]}
    assert PASSWORD not in json.dumps(report)


NEIGHBOUR_SECRETS = {
    "rails.rb": ("Rails.application.configure do\n  config.secret_key_base = \"{s}\"\n"
                 "  system(params[:cmd])\nend\n", HEX * 2),
    "envset.py": ('import os\nos.environ["SECRET_KEY"] = "{s}"\nos.system(input())\n', HEX),
    "dictset.py": ('import os\ncfg = {{}}\ncfg["api_key"] = "{s}"\nos.system(input())\n', HEX),
    "suffix.py": ("import os\nAPI_KEY_PROD = '{s}'\nos.system(input())\n", HEX),
    "bearer.py": ('import os\nH = {{"Authorization": "Bearer {s}"}}\nos.system(input())\n',
                  "abcdefghijklmnopqrstuvwxyz" + "ABCD"),
    "aws.py": ('import os\naws_secret_access_key = "{s}"\nos.system(input())\n',
               "wJalrXUtnFEMI/K7MDENG/" + "bPxRfiCYEXAMPLEKEY"),
    "conn.py": ('import os\nDSN = "Server=db;Database=app;Password={s};"\nos.system(input())\n',
                PASSWORD),
    "redis.py": ('import os\nURL = "redis://:{s}@cache:6379/0"\nos.system(input())\n', PASSWORD),
}


@pytest.mark.parametrize("name", list(NEIGHBOUR_SECRETS))
def test_a_credential_on_a_neighbouring_line_never_leaks(repo: Path, capsys, name: str) -> None:
    template, secret = NEIGHBOUR_SECRETS[name]
    _write(repo, f"app/{name}", template.format(s=secret))

    _, report = _json_run(capsys, "--severity", "info", f"app/{name}")

    assert report["findings"], "no finding, so no window to check"
    assert secret not in json.dumps(report)


# --- 10. stderr is advisory: failing to write it changes nothing ------------------


def _cli_with_stderr(cwd: Path, stderr: int, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "cwe_agent.offline", *args],
        cwd=cwd, env=_env(), stdout=subprocess.PIPE, stderr=stderr, text=True, timeout=300,
    )


@pytest.mark.skipif(not Path("/dev/full").exists(), reason="needs /dev/full")
@pytest.mark.parametrize(("args", "expected", "verdict"), [
    (("clean.py",), 0, "No blocking findings."),
    (("bad.py",), 1, "blocking finding(s)"),
    (("--format", "json", "clean.py"), 0, '"schema": 1'),
    (("nope.py",), 2, ""),
    (("--bogus", "clean.py"), 2, ""),
], ids=["pass", "blocked", "json", "missing-file", "bad-option"])
def test_an_unwritable_stderr_never_changes_the_verdict(
    repo: Path, args: tuple[str, ...], expected: int, verdict: str,
) -> None:
    _write(repo, "clean.py", CLEAN)
    _write(repo, "bad.py", COMMAND_INJECTION)

    with open("/dev/full", "w") as full:
        proc = _cli_with_stderr(repo, full.fileno(), *args)

    assert proc.returncode == expected
    assert verdict in proc.stdout


def test_a_stderr_whose_reader_is_gone_never_changes_the_verdict(repo: Path) -> None:
    _write(repo, "clean.py", CLEAN)
    _write(repo, "bad.py", COMMAND_INJECTION)
    results = {}
    for name in ("clean.py", "bad.py"):
        read_end, write_end = os.pipe()
        os.close(read_end)
        try:
            proc = _cli_with_stderr(repo, write_end, name)
        finally:
            os.close(write_end)
        results[name] = (proc.returncode, proc.stdout)

    assert results["clean.py"][0] == 0 and "No blocking findings." in results["clean.py"][1]
    assert results["bad.py"][0] == 1 and "blocking finding(s)" in results["bad.py"][1]


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="needs /bin/sh to close fd 2")
def test_a_closed_stderr_keeps_the_json_report_intact(repo: Path) -> None:
    _write(repo, "clean.py", CLEAN)

    proc = subprocess.run(
        ["/bin/sh", "-c",
         f'exec "{sys.executable}" -m cwe_agent.offline --format json clean.py 2>&-'],
        cwd=repo, env=_env(), capture_output=True, text=True, timeout=300,
    )

    assert proc.returncode == 0
    assert json.loads(proc.stdout)["schema"] == 1


def test_a_stdout_whose_reader_is_gone_is_a_quiet_tool_error(repo: Path) -> None:
    _write(repo, "bad.py", COMMAND_INJECTION)
    read_end, write_end = os.pipe()
    os.close(read_end)
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "cwe_agent.offline", "bad.py"],
            cwd=repo, env=_env(), stdout=write_end, stderr=subprocess.PIPE, text=True,
            timeout=300,
        )
    finally:
        os.close(write_end)

    assert proc.returncode == 2
    assert "cannot write the report" in proc.stderr
    assert "Exception ignored" not in proc.stderr and "Traceback" not in proc.stderr


# --- 11. cleanup survives a second exit signal --------------------------------------


@pytest.mark.skipif(not hasattr(os, "kill") or sys.platform == "win32", reason="POSIX signals")
def test_a_second_exit_signal_during_cleanup_still_removes_the_tree(
    repo: Path, monkeypatch, capsys,
) -> None:
    """The first SIGTERM stops the scan; a second one arriving while the
    temporary copy is being removed must not abort the removal."""
    import signal as _signal

    _write(repo, "src/app.py", CLEAN)
    made: list[Path] = []
    removing: list[Path] = []
    real_temp, real_rmtree = offline._neutral_temp, offline.shutil.rmtree

    def _temp() -> Path:
        made.append(real_temp())
        return made[-1]

    def _skills(_root: str, _errors: list) -> list:
        os.kill(os.getpid(), _signal.SIGTERM)
        return []

    def _rmtree(path, *args, **kwargs) -> None:
        if Path(path) in made:  # only the run's own cleanup, never a fixture's
            made.remove(Path(path))
            removing.append(Path(path))
            os.kill(os.getpid(), _signal.SIGTERM)
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(offline, "_neutral_temp", _temp)
    monkeypatch.setattr(offline, "_run_skills", _skills)
    monkeypatch.setattr(offline.shutil, "rmtree", _rmtree)

    with pytest.raises(SystemExit) as exc:
        main(["src/app.py"])
    capsys.readouterr()

    assert exc.value.code == 128 + _signal.SIGTERM
    assert removing and not [p for p in removing if p.exists()]
    assert _signal.getsignal(_signal.SIGTERM) is not offline._raise_exit


# --- 12. an empty --root is a usage error, not a silent discovery -----------------


def test_an_empty_root_is_a_usage_error(pruned_project: Path, capsys) -> None:
    code = main(["--root", "", "app/a.py"])
    err = capsys.readouterr().err

    assert code == 2
    assert "--root" in err


# --- 13. .gitmodules is read the way git reads it ----------------------------------


@pytest.mark.parametrize(("declared", "rel"), [
    ('[submodule "x;y"]\n\tpath = "lib;v1"\n', "lib;v1"),
    ('[submodule "z"]\n\tpath = "lib #2"\n', "lib #2"),
    ('[submodule "q"]\n\tpath = "lib"\n', "lib"),
    ('[Submodule "q"]\n\tPath = lib\n', "lib"),
    ('[submodule "q"]\n\tpath = lib ; a comment\n', "lib"),
    ('[submodule "q"]\n\tpath = lib # a comment\n', "lib"),
    ('[submodule "q"]\n\tpath = "dir\\\\sub"\n', "dir\\sub"),
], ids=["semicolon", "hash", "quoted", "case", "semicolon-comment", "hash-comment", "escape"])
def test_a_submodule_path_git_writes_quoted_is_recognised(
    repo: Path, capsys, declared: str, rel: str,
) -> None:
    (repo / rel).mkdir()
    _write(repo, ".gitmodules", declared)
    _write(repo, "app.py", COMMAND_INJECTION)

    code, report = _json_run(capsys, "app.py", rel)

    assert code == 1
    assert {r["path"] for r in report["not_scanned"]} == {str(repo / rel)}
    assert "submodule" in report["not_scanned"][0]["reason"]


@pytest.mark.parametrize("declared", [
    "[foo]\n\tpath = lib\n",
    '[submodule "q"]\n\turl = x\n[core]\n\tpath = lib\n',
    '[submodule "q"]\n\tsubpath = lib\n',
], ids=["other-section", "later-section", "other-key"])
def test_a_path_key_outside_a_submodule_section_declares_nothing(
    repo: Path, capsys, declared: str,
) -> None:
    (repo / "lib").mkdir()
    _write(repo, ".gitmodules", declared)
    _write(repo, "app.py", COMMAND_INJECTION)

    code = main(["app.py", "lib"])
    err = capsys.readouterr().err

    assert code == 2
    assert "is a directory" in err


# --- 14. every Bidi_Control and invisible format character is escaped ------------


@pytest.mark.parametrize("mark", ["\u061c", "\u2028", "\u2060", "\xad"],
                         ids=["alm", "line-sep", "word-joiner", "soft-hyphen"])
def test_an_invisible_format_character_in_a_file_name_is_escaped(
    repo: Path, capsys, mark: str,
) -> None:
    name = f"a{mark}b.py"
    _write(repo, name, COMMAND_INJECTION)

    code = main([name])
    out, err = capsys.readouterr()

    assert code == 1
    assert mark not in out and mark not in err
    assert mark.encode("unicode_escape").decode("ascii") in out


def test_the_guide_and_changelog_carry_no_invisible_format_characters() -> None:
    """A raw bidi override renders the rest of its line reversed (Trojan Source)."""
    import unicodedata

    for path in (GUIDE, _REPO_ROOT / "CHANGELOG.md"):
        text = path.read_text(encoding="utf-8")
        hidden = {f"U+{ord(c):04X}" for c in text if unicodedata.category(c) in {"Cf", "Zl", "Zp"}}
        assert not hidden, f"{path.name}: {sorted(hidden)}"


# --- 15. a file a skill reads by NAME is over the cap, not out of the set ----------


@pytest.mark.parametrize("rel", ["cfg/.env.production", "static/.env", "cfg/.envrc",
                                 "cfg/server.key", "cfg/site.pem"])
def test_an_over_cap_file_a_skill_reads_by_name_names_only_the_cap(
    repo: Path, capsys, rel: str,
) -> None:
    _write(repo, "src/cmd.py", COMMAND_INJECTION)
    _sparse(repo / rel, MAX_FILE_SIZE + 4096)

    code, report = _json_run(capsys, "src/cmd.py", rel)

    assert code == 1
    assert _reasons(report)[str(repo / rel)] == offline._STAND_IN


# --- 16. the gate's accounting and output contract, edge by edge -----------------


def test_a_working_directory_that_is_the_pruned_directory_is_a_usage_error(
    pruned_project: Path, monkeypatch, capsys,
) -> None:
    monkeypatch.chdir(pruned_project.parent)

    code = main(["proj/app/a.py"])
    capsys.readouterr()

    assert code == 2


def test_a_sibling_of_a_pruned_directory_is_not_inside_it(
    request: pytest.FixtureRequest, monkeypatch, capsys,
) -> None:
    outer = neutral_dir(request) / "outer"
    (outer / ".git").mkdir(parents=True)
    _write(outer, "buildtools/bad.py", COMMAND_INJECTION)
    _write(outer, "build/x.py", COMMAND_INJECTION)
    monkeypatch.chdir(outer / "buildtools")

    code = main(["bad.py", "../build/x.py"])
    capsys.readouterr()

    assert code == 1


def test_a_file_exactly_at_the_read_cap_is_copied_and_scanned(repo: Path, capsys) -> None:
    head = COMMAND_INJECTION
    _write(repo, "src/edge.py", head + "#" * (MAX_FILE_SIZE - len(head) - 1) + "\n")
    assert (repo / "src" / "edge.py").stat().st_size == MAX_FILE_SIZE

    code, report = _json_run(capsys, "src/edge.py")

    assert code == 1
    assert report["scanned"] == [str(repo / "src" / "edge.py")]


def test_a_name_only_finding_counts_its_file_as_scanned(repo: Path, capsys) -> None:
    _sparse(repo / "public" / "x.sqlite", 4096)

    code = main(["public/x.sqlite"])
    err = capsys.readouterr().err

    assert code == 1
    assert "scanned 1 of 1 file(s)" in err


def test_the_json_report_has_exactly_the_schema_1_keys(repo: Path, capsys) -> None:
    _write(repo, "clean.py", CLEAN)

    code, report = _json_run(capsys, "clean.py")

    assert code == 0
    assert set(report) == {"schema", "root", "severity", "findings", "blocking", "errors",
                           "scanned", "not_scanned", "outside_root"}


def test_the_lefthook_example_runs_with_the_recommended_install() -> None:
    """The recommended install is the PYTHONPATH module form, with no console
    script, so the hook example must call the module."""
    text = _guide()
    section = text[text.index("## Pre-commit hook (lefthook)"):]
    block = _blocks(section)[0]

    assert "-m cwe_agent.offline" in block
    assert "PYTHONPATH=" in block
