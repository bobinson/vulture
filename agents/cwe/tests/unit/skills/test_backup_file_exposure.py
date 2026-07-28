"""Exposed backup/shadow files are themselves a finding — feature 0068.

A readable `package.json.bak`, `config.php~` or `.env.old` sitting in a served
tree leaks whatever the live file no longer contains: removed credentials, old
dependency pins, prior logic. In OWASP juice-shop this is a deliberate
challenge (`ftp/package.json.bak`).

CWE-530 (Exposure of Backup File) is the precise weakness but is NOT mapped in
the OWASP 2025 edition, so findings are categorised as its mapped parent
CWE-552 (Files or Directories Accessible to External Parties -> A01) and name
CWE-530 in the text. That keeps the mapping honest — we do not invent an OWASP
mapping — while still reporting the specific weakness to the operator.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.info_exposure_check import check_information_exposure


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_information_exposure(str(root))["findings"]


def _backup_findings(findings):
    return [f for f in findings if f.get("category") == "CWE-552"]


class TestBackupExposure:
    def test_backup_of_source_is_reported(self):
        f = _run({"server.ts.bak": "const dbPassword = 'hunter2'\n"})
        hits = _backup_findings(f)
        assert hits, "a .bak copy of source must be reported as an exposure"
        assert "530" in (hits[0]["description"] + hits[0]["title"]), \
            "must name the precise weakness CWE-530 in the text"

    def test_editor_and_rotation_shadows_reported(self):
        for name in ("app.js~", "config.yml.old", "routes.ts.bak.1", "index.php.orig"):
            assert _backup_findings(_run({name: "x = 1\n"})), f"{name} not reported"

    def test_served_location_raises_severity(self):
        low = _backup_findings(_run({"src/util.ts.bak": "x=1\n"}))
        served = _backup_findings(_run({"ftp/package.json.bak": '{"a":1}\n'}))
        assert low and served
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        assert order[served[0]["severity"]] > order[low[0]["severity"]], \
            "a backup under a publicly-served dir must outrank one buried in src/"

    def test_live_files_not_flagged(self):
        f = _run({"server.ts": "const a = 1\n", "package.json": '{"a":1}\n'})
        assert not _backup_findings(f), "non-backup files must never be flagged"
