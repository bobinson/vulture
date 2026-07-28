"""Minified/bundled vendor files must not be scanned as source.

A minified bundle is one enormous line of third-party code. Every line-oriented
pattern in every skill fires against it, the reported line number is always 1,
and the "fix" is meaningless because the file is generated from a dependency we
do not control.

On OWASP juice-shop this dominated the XSS results: 14 of 19 CWE-79 rows came
from two vendored bundles —

    frontend/src/assets/private/dat.gui.min.js   12 rows
    frontend/src/assets/private/stats.min.js      2 rows

— which made the remaining 5 genuine findings impossible to see and left the
real strength of the injection category unassessable.

Exclusion is by filename, deterministic, and overridable with
VULTURE_SCAN_MINIFIED=true for operators who do want bundle coverage.
Backup copies of bundles are unaffected: exposure reporting walks filenames
separately (scan_backup_files), so `app.min.js.bak` is still reported as an
exposed backup even though its contents are not scanned.
"""

import os
import tempfile
from pathlib import Path

from shared.tools.file_scanner import (
    is_minified_name,
    scan_backup_files,
    scan_code_files,
)


def _names(files: dict[str, str], **kw) -> set[str]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return {p.name for p in scan_code_files(str(root), **kw)}


class TestIsMinifiedName:
    def test_recognises_minified_forms(self):
        for name in (
            "dat.gui.min.js",
            "stats.min.js",
            "app.min.css",
            "vendor.min.mjs",
            "jquery-min.js",
            "runtime.bundle.js",
        ):
            assert is_minified_name(name), f"{name} should be treated as minified/bundled"

    def test_does_not_over_match(self):
        for name in (
            "server.ts",
            "minify.ts",
            "minimist.js",
            "admin.js",
            "mining.py",
            "bundle_helper.ts",
        ):
            assert not is_minified_name(name), f"{name} must NOT be treated as minified"


class TestScannerSkipsMinified:
    def test_minified_bundles_are_not_scanned(self):
        got = _names({
            "app.ts": "const x = 1\n",
            "assets/dat.gui.min.js": "!function(){}();\n",
            "assets/stats.min.js": "!function(){}();\n",
        })
        assert got == {"app.ts"}, f"expected only app.ts, got {got}"

    def test_source_alongside_bundle_is_still_scanned(self):
        # NB: not `vendor/` — that name is in SKIP_DIRS already. juice-shop
        # keeps its three.js copies under assets/private/, which is scanned.
        got = _names({
            "assets/private/OrbitControls.js": "function OrbitControls () {}\n",
            "assets/private/three.min.js": "!function(){}();\n",
        })
        assert got == {"OrbitControls.js"}, \
            f"non-minified vendored source is still source; got {got}"

    def test_opt_in_env_restores_bundle_coverage(self):
        os.environ["VULTURE_SCAN_MINIFIED"] = "true"
        try:
            got = _names({"a.ts": "x\n", "b.min.js": "!function(){}();\n"})
            assert got == {"a.ts", "b.min.js"}, \
                f"VULTURE_SCAN_MINIFIED=true must restore coverage; got {got}"
        finally:
            del os.environ["VULTURE_SCAN_MINIFIED"]


class TestBackupOfBundleStillReported:
    def test_minified_backup_is_still_enumerated_as_a_backup(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "app.min.js.bak").write_text("!function(){}();\n")
            backups = {p.name for p in scan_backup_files(str(root))}
            scanned = {p.name for p in scan_code_files(str(root))}
        assert backups == {"app.min.js.bak"}, \
            "a bundle backup is still an exposed backup even if unparsed"
        assert scanned == set(), "its contents must not be scanned as source"
