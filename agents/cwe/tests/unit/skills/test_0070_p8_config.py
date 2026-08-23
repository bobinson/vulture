"""Feature 0070 P8 — configuration_check reachability additions (group `config`).

Two rules land here. Both are keyed on an idiom that IS the weakness, so the
clean twin beside each positive differs by one token only.

  CWE-276  Incorrect Default Permissions
           The *default* that every resource created or installed by a recipe
           inherits is world-modifiable: a cleared creation mask (`umask 0`),
           a recursive install-time grant (`chmod -R 777`), a Docker build
           `--chmod=` world-writable copy, or a mount-wide `defaultMode`.
           Deliberately DISJOINT from the pre-existing CWE-732 arms, which
           name one specific resource (`chmod 777 /var/data`,
           `os.chmod(p, 0o777)`, `mode: 0777`). A line can only ever produce
           one permission row, and the twins below pin that boundary:
           `umask 077` / `chmod -R 755` / `--chmod=644` / `defaultMode: 0400`
           are all correct and must stay silent.

  CWE-15   External Control of System or Configuration Setting
           A request-derived value (or a request-derived KEY) is written into
           a process-wide setting — the environment, a JVM system property, or
           a PHP ini entry. Both halves must be on the line: the sink alone is
           ordinary configuration code, and the twins are exactly that.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.configuration_check import check_configuration


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_configuration(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f["category"] == f"CWE-{cwe}"]


# ------------------------------------------------------------------ CWE-276


def test_cleared_creation_mask_in_python_is_276() -> None:
    rows = _of(_run({"bootstrap.py": (
        "def prepare(base):\n"
        "    os.umask(0)\n"
        "    os.makedirs(base)\n"
    )}), "276")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 2


def test_restrictive_creation_mask_in_python_is_clean() -> None:
    assert _of(_run({"bootstrap.py": (
        "def prepare(base):\n"
        "    os.umask(0o077)\n"
        "    os.makedirs(base)\n"
    )}), "276") == []


def test_cleared_creation_mask_in_shell_script_is_276() -> None:
    rows = _of(_run({"provision.sh": (
        "#!/bin/sh\n"
        "umask 000\n"
        "mkdir -p /srv/app\n"
    )}), "276")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 2


def test_restrictive_creation_mask_in_shell_script_is_clean() -> None:
    assert _of(_run({"provision.sh": (
        "#!/bin/sh\n"
        "umask 077\n"
        "mkdir -p /srv/app\n"
    )}), "276") == []


def test_recursive_world_writable_grant_is_276() -> None:
    rows = _of(_run({"Dockerfile": (
        "FROM alpine:3\n"
        "COPY . /srv/app\n"
        "RUN chmod -R 777 /srv/app\n"
    )}), "276")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 3


def test_recursive_group_readable_grant_is_clean() -> None:
    assert _of(_run({"Dockerfile": (
        "FROM alpine:3\n"
        "COPY . /srv/app\n"
        "RUN chmod -R 755 /srv/app\n"
    )}), "276") == []


def test_recursive_symbolic_world_write_is_276() -> None:
    rows = _of(_run({"provision.sh": (
        "#!/bin/sh\n"
        "chmod -R a+w /srv/app\n"
    )}), "276")
    assert len(rows) == 1


def test_recursive_owner_write_is_clean() -> None:
    assert _of(_run({"provision.sh": (
        "#!/bin/sh\n"
        "chmod -R u+w /srv/app\n"
    )}), "276") == []


def test_build_copy_world_writable_mode_is_276() -> None:
    rows = _of(_run({"Dockerfile": (
        "FROM alpine:3\n"
        "COPY --chmod=666 ./app /srv/app\n"
    )}), "276")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 2


def test_build_copy_read_only_mode_is_clean() -> None:
    assert _of(_run({"Dockerfile": (
        "FROM alpine:3\n"
        "COPY --chmod=644 ./app /srv/app\n"
    )}), "276") == []


def test_volume_default_mode_world_writable_is_276() -> None:
    rows = _of(_run({"deployment.yaml": (
        "volumes:\n"
        "  - secret:\n"
        "      secretName: api-credentials\n"
        "      defaultMode: 0777\n"
    )}), "276")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 4


def test_volume_default_mode_owner_only_is_clean() -> None:
    assert _of(_run({"deployment.yaml": (
        "volumes:\n"
        "  - secret:\n"
        "      secretName: api-credentials\n"
        "      defaultMode: 0400\n"
    )}), "276") == []


def test_single_resource_grant_stays_732_and_does_not_stack() -> None:
    """`chmod 777 <one path>` is CWE-732; 276 must not double-report it."""
    findings = _run({"deploy.yml": (
        "steps:\n"
        "  - run: chmod 777 /var/data\n"
    )})
    assert len(_of(findings, "732")) == 1
    assert _of(findings, "276") == []


def test_shell_walk_reports_only_the_default_permission_weakness() -> None:
    """`chmod 777 <one path>` in a script belongs to the access-control skill.

    The shell walk exists for the default-permission idioms only. Emitting the
    single-resource CWE-732 arm over the same lines would put a second row on a
    line another skill already reports (skill findings are not deduplicated
    against each other).
    """
    findings = _run({"provision.sh": (
        "#!/bin/sh\n"
        "chmod 777 /var/data\n"
    )})
    assert findings == []


def test_default_permission_line_yields_exactly_one_permission_row() -> None:
    """One line, one permission finding — never a 276 and a 732 together."""
    findings = _run({"bootstrap.py": (
        "def prepare():\n"
        "    os.umask(0)\n"
    )})
    perms = [f for f in findings if f["category"] in ("CWE-276", "CWE-732")]
    assert len(perms) == 1
    assert perms[0]["category"] == "CWE-276"


# ------------------------------------------------------------------- CWE-15


def test_env_assigned_from_request_value_is_15() -> None:
    rows = _of(_run({"handler.js": (
        "function apply(req, res) {\n"
        "  process.env.LOG_LEVEL = req.query.level\n"
        "  res.end('ok')\n"
        "}\n"
    )}), "15")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 2


def test_env_assigned_from_constant_is_clean() -> None:
    assert _of(_run({"handler.js": (
        "function apply(req, res) {\n"
        "  process.env.LOG_LEVEL = 'info'\n"
        "  res.end('ok')\n"
        "}\n"
    )}), "15") == []


def test_env_key_taken_from_request_is_15() -> None:
    rows = _of(_run({"handler.js": (
        "function apply(req, res) {\n"
        "  process.env[req.body.name] = 'on'\n"
        "}\n"
    )}), "15")
    assert len(rows) == 1


def test_env_read_by_request_key_is_clean() -> None:
    """Reading a setting is not controlling it."""
    assert _of(_run({"handler.js": (
        "function apply(req, res) {\n"
        "  res.end(process.env[req.body.name])\n"
        "}\n"
    )}), "15") == []


def test_python_environ_assigned_from_request_is_15() -> None:
    rows = _of(_run({"views.py": (
        "def update(request):\n"
        "    os.environ['UPLOAD_DIR'] = request.args.get('dir')\n"
    )}), "15")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 2


def test_python_environ_assigned_from_settings_is_clean() -> None:
    assert _of(_run({"views.py": (
        "def update(settings):\n"
        "    os.environ['UPLOAD_DIR'] = settings.upload_dir\n"
    )}), "15") == []


def test_system_property_from_request_parameter_is_15() -> None:
    rows = _of(_run({"Settings.java": (
        "public class Settings {\n"
        "  void apply(HttpServletRequest request) {\n"
        "    System.setProperty(\"user.timezone\", request.getParameter(\"tz\"));\n"
        "  }\n"
        "}\n"
    )}), "15")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 3


def test_system_property_from_literal_is_clean() -> None:
    assert _of(_run({"Settings.java": (
        "public class Settings {\n"
        "  void apply() {\n"
        "    System.setProperty(\"user.timezone\", \"UTC\");\n"
        "  }\n"
        "}\n"
    )}), "15") == []


def test_php_ini_set_from_superglobal_is_15() -> None:
    rows = _of(_run({"settings.php": (
        "<?php\n"
        "ini_set('include_path', $_GET['path']);\n"
    )}), "15")
    assert len(rows) == 1
    assert rows[0]["line_start"] == 2


def test_php_ini_set_from_literal_is_clean() -> None:
    assert _of(_run({"settings.php": (
        "<?php\n"
        "ini_set('display_errors', '0');\n"
    )}), "15") == []


def test_external_control_line_yields_exactly_one_row() -> None:
    findings = _run({"handler.js": (
        "function apply(req, res) {\n"
        "  process.env[req.body.name] = req.body.value\n"
        "}\n"
    )})
    on_line = [f for f in findings if f["line_start"] == 2]
    assert len(on_line) == 1
    assert on_line[0]["category"] == "CWE-15"
