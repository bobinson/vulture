"""SOC2 rules report what a line does, not a word that appears in it.

Business contract
-----------------
A self-scan reported rows that describe no unsafe deployment and no
unaudited data change:

* ``soc2.change_mgmt.unsafe_deploy``: ``rsync`` matched anywhere, in any case,
  so ``fs.mkdirSync``/``readdirSync``, a docstring's ``mkdirsync`` and a local
  ``rsync -a`` into a staging directory were all "manual deployments". rsync
  and scp now count only as whole commands that copy to ANOTHER HOST: an
  operand of remote shape (``[user@]host:path``, ``host:`` for the remote home
  directory, ``rsync://``, ``host::module``) or a remote shell option
  (``-e ssh``, ``--rsh``) is reported at medium. The user and host may be
  filled in at run time -- ``"$HOST":``, ``$(HOST)``, ``${{ secrets.H }}``,
  ``{{ host }}``, ``%s``, ``{}`` -- or concatenated (``host + ":" + dest``);
  an option value (``--chown=www:www``) or a ``key: value`` pair is no host; a destination held whole in one variable
  (``rsync dist/ "$TARGET"``) may be remote, and is reported at low. A
  command split over ``\\`` continuation lines is read whole and reported at
  its first line. Comments are not commands; quoted text is, since a
  command's operands are usually quoted -- unless the statement only displays
  it (``echo "scp ... phone:~/"``, ``print(...)``), which runs nothing.
* ``soc2.access_logging.missing_audit_log``: any ``def create_/update_/delete_``
  in a file without logging was a high finding pinned to line 1, including a
  developer tool's ``update_snapshot(rules_dir, name, entry)``. A data change
  needs an audit record when it is made FOR someone, so that arm now requires
  an actor in scope -- a parameter whose name denotes a principal or a request
  (``request``, ``current_user``, ``session``, ``username``, ``caller``...), or
  a body that uses one as a value (``self.request.user``, ``current_user.id``;
  a called ``self._request(...)`` sends a request, it is no caller) -- and is
  reported at the ``def`` line. Strings and comments are not read: a ``")"``
  default does not end the parameter list, and a docstring that mentions a
  user is no actor. The login/logout/auth arms are unchanged:
  unconditional, and reported at line 1.

Fixture layout (``fixtures/rule_precision``): one unit per directory under
``pos/`` (reported) or ``neg/`` (clean), each scanned on its own from a copy
outside any test path, since both rules skip test files.
"""
from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from shared.tools.file_scanner import clear_caches, is_test_file, scan_code_files
from soc2_agent.skills.access_logging import check_access_logging
from soc2_agent.skills.change_management import check_change_management

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "rule_precision"
DEPLOY = "soc2.change_mgmt.unsafe_deploy"
ACCESS = "soc2.access_logging.missing_audit_log"

# unit-name prefix -> (skill, the one check id its units are asserted for)
RULES: dict[str, tuple[Callable[[str], dict], str]] = {
    "deploy_": (check_change_management, DEPLOY),
    "access_": (check_access_logging, ACCESS),
}

# pos unit -> every finding it must yield:
# (path in the unit, text on the anchored line, severity).
# ``None`` anchors a file-level row at line 1.
REPORTED: dict[str, list[tuple[str, str | None, str]]] = {
    "deploy_remote_rsync": [("release.sh", "rsync -avz dist/", "medium")],
    "deploy_remote_scp": [("ship.sh", "scp app.tar", "medium")],
    "deploy_remote_continuation": [("publish.sh", "rsync -avz --delete", "medium")],
    "deploy_remote_daemon_and_rsh": [
        ("mirror.sh", "rsync://", "medium"),
        ("mirror.sh", "::site", "medium"),
        ("mirror.sh", "-e ssh", "medium"),
    ],
    "deploy_remote_in_string": [("push.py", '"rsync"', "medium")],
    "deploy_remote_after_echo": [("release.sh", "rsync -az", "medium")],
    "deploy_opaque_target": [("sync.sh", 'rsync -az dist/ "$TARGET"', "low")],
    "deploy_remote_home_dir": [("push.sh", "rsync -avz dist/ prod:", "medium")],
    "deploy_quoted_placeholders": [
        ("ship.sh", '"$HOST":/srv/app', "medium"),
        ("ship.sh", '"$USER"@"$HOST":/srv', "medium"),
    ],
    "deploy_ci_expression": [
        (".github/workflows/publish.yml", "- run: rsync", "medium"),
        (".github/workflows/publish.yml", "MIRROR_HOST", "medium"),
    ],
    "deploy_template_host": [("site.yml", "{{ inventory_hostname }}:/srv", "medium")],
    "deploy_make_variables": [
        ("Makefile", "$(DEPLOY_HOST):/var/www", "medium"),
        ("Makefile", "$(USER)@$(HOST):", "medium"),
    ],
    "deploy_format_string": [
        ("push.py", '"%s@%s:/srv"', "medium"),
        ("push.go", 'fmt.Sprintf("%s:%s"', "medium"),
    ],
    "deploy_concatenation": [
        ("push.py", 'host + ":" + dest', "medium"),
        ("push.go", 'host+":"+dest', "medium"),
    ],
    "access_request_handler": [("views.py", "def delete_user(", "high")],
    "access_multiline_signature": [("profile.py", "def update_profile(", "high")],
    "access_session_method": [("accounts.py", "def update_email(", "high")],
    "access_identifier_param": [("passwords.py", "def update_password(", "high")],
    "access_login_unconditional": [("auth.py", None, "high")],
    "access_view_receiver": [("views.py", "def delete_item(", "high")],
    "access_global_current_user": [("orders.py", "def create_order(", "high")],
    "access_caller_param": [("records.py", "def delete_record(", "high")],
    "access_paren_in_default": [("titles.py", "def update_title(", "high")],
}
CLEAN = (
    "deploy_local_staging_copy",
    "deploy_sync_suffix_calls",
    "deploy_package_install",
    "deploy_trailing_comment",
    "deploy_echoed_instruction",
    "deploy_option_values",
    "access_offline_tool",
    "access_scaffold_dirs",
    "access_body_prose_only",
    "access_body_outbound_request",
)


def _neutral_copy(src: Path, tmp_path: Path) -> Path:
    """Copy ``src`` where no file is classified as a test, so a scan is not vacuous."""
    root = tmp_path / "fixcorpus" / "app"
    shutil.copytree(src, root)
    files = [p for p in root.rglob("*") if p.is_file()]
    assert files and not any(map(is_test_file, files)), f"copy at {root} is not neutral"
    return root


def _scan(kind: str, unit: str, tmp_path: Path) -> tuple[Path, list[dict]]:
    skill, check = next(rule for prefix, rule in RULES.items() if unit.startswith(prefix))
    root = _neutral_copy(FIXTURES / kind / unit, tmp_path)
    clear_caches()
    # Population floor: a file the scanner never enumerates would pass "clean".
    files = {p for p in root.rglob("*") if p.is_file()}
    assert files <= set(map(Path, scan_code_files(str(root)))), "fixture file not scanned"
    return root, [f for f in skill(str(root))["findings"] if f["check_id"] == check]


def _line_of(path: Path, text: str | None) -> int:
    if text is None:
        return 1
    lines = path.read_text().splitlines()
    hits = [n for n, line in enumerate(lines, start=1) if text in line]
    assert len(hits) == 1, f"anchor text {text!r} must occur once in {path.name}"
    return hits[0]


def test_every_unit_is_listed() -> None:
    """A fixture unit without an expectation would never be asserted."""
    on_disk = {p.name for kind in ("pos", "neg") for p in (FIXTURES / kind).iterdir()}
    assert on_disk == set(REPORTED) | set(CLEAN)


@pytest.mark.parametrize("unit", sorted(REPORTED))
def test_unsafe_practice_is_reported_at_its_line(unit: str, tmp_path: Path) -> None:
    root, findings = _scan("pos", unit, tmp_path)
    got = sorted(
        (Path(f["file_path"]).relative_to(root).as_posix(), f["line_start"], f["severity"])
        for f in findings
    )
    want = sorted((rel, _line_of(root / rel, text), sev) for rel, text, sev in REPORTED[unit])
    assert got == want


@pytest.mark.parametrize("unit", CLEAN)
def test_word_without_the_practice_is_not_reported(unit: str, tmp_path: Path) -> None:
    _, findings = _scan("neg", unit, tmp_path)
    assert findings == []
