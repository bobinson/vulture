"""Backup-file exposure must not inherit the shadowed file's scan exclusions.

`_check_backup_exposure` was invoked from inside the `scan_code_files()` loop,
so a shadow copy was only ever reported if the scanner yielded it — and marker
stripping makes a shadow copy inherit the underlying type's EXCLUSION rules:

    ftp/package-lock.json.bak  -> effective name 'package-lock.json' is in
                                  SKIP_FILES (lock files are skipped) -> never yielded
    ftp/coupons_2013.md.bak    -> effective suffix '.md' is not a code
                                  extension -> never yielded
    ftp/package.json.bak       -> yielded via manifest extras -> the only finding

So juice-shop's three backup files produced exactly one CWE-552 row. Exposure
is a property of the FILENAME — a readable `package-lock.json.bak` in a served
directory leaks its contents whether or not we would parse those contents.

Separately, the 512KB read cap silently dropped ftp/package-lock.json.bak
(750,353 bytes), losing its dependency findings entirely. A dependency
manifest is exactly the file whose size correlates with how much there is to
find, so the cap must not apply to it.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.dependency_check import check_dependency_security
from cwe_agent.skills.info_exposure_check import check_information_exposure


def _tree(files: dict[str, str]) -> tempfile.TemporaryDirectory:
    d = tempfile.TemporaryDirectory()
    root = Path(d.name)
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


def _backup_findings(root: str) -> list[dict]:
    fs = check_information_exposure(root)["findings"]
    return [f for f in fs if f.get("category") == "CWE-552"]


class TestBackupExposureIgnoresContentGates:
    def test_lockfile_backup_is_reported(self):
        """SKIP_FILES applies to parsing a lock file, not to exposing it."""
        d = _tree({"ftp/package-lock.json.bak": '{"lockfileVersion": 2}\n'})
        hits = _backup_findings(d.name)
        d.cleanup()
        assert hits, "package-lock.json.bak must be reported even though lock files are skipped"

    def test_non_code_extension_backup_is_reported(self):
        """A .md backup is still an exposed backup."""
        d = _tree({"ftp/coupons_2013.md.bak": "n<MibgC7sn ...\n"})
        hits = _backup_findings(d.name)
        d.cleanup()
        assert hits, "coupons_2013.md.bak must be reported even though .md is not scanned"

    def test_juiceshop_ftp_directory_reports_all_three(self):
        """The exact juice-shop case: three backup files, three findings."""
        d = _tree({
            "ftp/coupons_2013.md.bak": "discount codes\n",
            "ftp/package-lock.json.bak": '{"lockfileVersion": 2}\n',
            "ftp/package.json.bak": '{"dependencies": {"lodash": "^4.17.0"}}\n',
        })
        hits = _backup_findings(d.name)
        names = sorted(Path(f["file_path"]).name for f in hits)
        d.cleanup()
        assert names == [
            "coupons_2013.md.bak",
            "package-lock.json.bak",
            "package.json.bak",
        ], f"expected all three backups reported, got {names}"

    def test_served_directory_raises_severity(self):
        d = _tree({"ftp/package-lock.json.bak": "{}\n"})
        hits = _backup_findings(d.name)
        d.cleanup()
        assert hits[0]["severity"] == "high", \
            "a backup under a publicly-served directory must be high severity"

    def test_no_duplicate_findings_for_a_scannable_backup(self):
        """A backup that IS also scanned must yield one exposure row, not two."""
        d = _tree({"server.ts.bak": "const x = 1\n"})
        hits = _backup_findings(d.name)
        d.cleanup()
        assert len(hits) == 1, f"expected exactly one exposure finding, got {len(hits)}"

    def test_ordinary_files_are_not_reported(self):
        d = _tree({"server.ts": "const x = 1\n", "package.json": "{}\n"})
        hits = _backup_findings(d.name)
        d.cleanup()
        assert not hits, "non-backup files must not be reported as exposures"


class TestLargeManifestIsNotSilentlyDropped:
    def _big_lock(self) -> str:
        """A package-lock.json comfortably over the 512KB read cap."""
        entries = []
        for i in range(4000):
            entries.append(
                f'    "node_modules/filler-package-{i}": {{\n'
                f'      "version": "1.0.{i}",\n'
                f'      "resolved": "https://registry.npmjs.org/filler-package-{i}",\n'
                f'      "integrity": "sha512-{"a" * 64}"\n'
                f'    }}'
            )
        return (
            '{\n  "lockfileVersion": 2,\n  "packages": {\n'
            + ",\n".join(entries)
            + ',\n    "node_modules/minimist": { "version": "0.0.8" }\n  }\n}\n'
        )

    def test_oversized_lockfile_is_still_audited(self):
        body = self._big_lock()
        assert len(body) > 512 * 1024, "fixture must exceed the read cap to be meaningful"
        d = _tree({"package-lock.json": body})
        fs = check_dependency_security(d.name)["findings"]
        d.cleanup()
        assert fs, "an oversized dependency manifest must still be audited, not silently skipped"
