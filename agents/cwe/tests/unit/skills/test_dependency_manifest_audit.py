"""Supply-chain (OWASP A03) detection in the dependency skill — feature 0068.

Three defects this pins, all found by scanning a real application tree:

1. ``package.json`` never reached the skill at all: the run loop applied
   ``is_generated_file()`` (which classifies package.json as generated) BEFORE
   the manifest dispatch, so the npm branch was dead for every JS/TS repo.
2. Backup manifests (``ftp/package.json.bak``) were invisible, yet those carry
   the dependency pins that were later removed — in one measured tree the
   ``epilogue-js`` typosquat lives only in the .bak.
3. CWE-1104 (unpinned/unmaintained component) was implemented only for
   requirements.txt, so the npm path could emit nothing that maps to A03.
   CWE-1104 and CWE-1357 are the A03-mapped CWEs a static skill can produce.
"""

import json
import tempfile
from pathlib import Path

from cwe_agent.skills.dependency_check import check_dependency_security


def _cats(findings, cwe):
    return [f for f in findings if f.get("category") == cwe]


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_dependency_security(str(root))["findings"]


class TestManifestIsActuallyRead:
    def test_package_json_reaches_the_skill(self):
        """Regression: is_generated_file() used to veto every package.json."""
        f = _run({"package.json": json.dumps({"dependencies": {"express": "^4.17.1"}})})
        assert _cats(f, "CWE-1104"), "package.json must be analysed, not skipped as 'generated'"

    def test_backup_manifest_is_audited(self):
        """A .bak manifest is still a manifest — and often the risky one."""
        f = _run({"ftp/package.json.bak": json.dumps({"dependencies": {"epilogue-js": "~0.7"}})})
        assert _cats(f, "CWE-1104"), "package.json.bak must be analysed as an npm manifest"
        assert any("epilogue-js" in (x.get("title", "") + x.get("description", "")) for x in f)


class TestNpmPinning:
    def test_caret_and_tilde_ranges_are_unpinned(self):
        f = _run({"package.json": json.dumps({
            "dependencies": {"a": "^1.2.3", "b": "~0.7"},
            "devDependencies": {"c": ">=2.0.0"},
        })})
        names = " ".join(x.get("title", "") + x.get("description", "") for x in _cats(f, "CWE-1104"))
        for pkg in ("a", "b", "c"):
            assert pkg in names, f"unpinned dep {pkg} not reported"

    def test_exact_pins_are_not_flagged(self):
        f = _run({"package.json": json.dumps({"dependencies": {"a": "1.2.3", "b": "4.5.6"}})})
        assert not _cats(f, "CWE-1104"), "exactly-pinned deps must not be flagged"

    def test_untrustworthy_specs_flagged_as_cwe_1357(self):
        """git/url/file specs bypass the registry — A03 'insufficiently
        trustworthy component'."""
        f = _run({"package.json": json.dumps({"dependencies": {
            "x": "git+https://github.com/evil/x.git",
            "y": "file:../vendor/y",
        }})})
        assert _cats(f, "CWE-1357"), "git/file specs must raise CWE-1357"

    def test_findings_point_at_the_real_line(self):
        body = '{\n  "dependencies": {\n    "alpha": "1.0.0",\n    "beta": "^2.0.0"\n  }\n}\n'
        f = _run({"package.json": body})
        beta = _cats(f, "CWE-1104")
        assert beta and beta[0]["line_start"] > 1, "must resolve the dependency's line, not hardcode 1"
