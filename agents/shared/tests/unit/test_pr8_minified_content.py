"""A bundle is recognised by its SHAPE, not only by its filename.

The name rule (`[.-]min` / `.bundle.js`) only catches the old naming
convention. Bundlers now emit chunk files whose name is nothing but a content
hash, or a plain route name inside a build directory, so a name-only rule lets
an entire build tree through: measured on a real build output, 101 generated
chunk files were enumerated as source and produced 224 line-1 findings for code
the project does not control.

The content rule closes that gap: a file whose long lines (over
``_MINIFIED_LINE_CHARS``) hold at least ``_MINIFIED_CHAR_FRACTION`` of its
characters is generated output whatever it is called.

It must not swallow real source. A hand-written file can hold ONE very long
line (an inlined data URI, a generated regex, an embedded SVG) and still be
source, which is why the rule is a fraction of the file rather than "has a long
line" — and why only bundler-produced text types are classified at all, leaving
prose, SQL and data formats alone.

Every fixture here is synthetic.
"""

import os
import tempfile
from pathlib import Path

from shared.tools.file_scanner import (
    _MINIFIED_CHAR_FRACTION,
    _MINIFIED_LINE_CHARS,
    clear_caches,
    is_minified_content,
    scan_code_files,
)

# One packed line, the way a bundler emits a chunk.
CHUNK_LINE = "!function(e,t){var n=" + ("a=b(c,d);" * 400) + "}(window,document);"
# A normal, hand-written line.
SRC_LINE = "export function handler(req, res) { return res.end('ok'); }"


def _write(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        p = root / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)


def _scanned(files: dict[str, str]) -> set[str]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        _write(root, files)
        clear_caches()
        return {p.name for p in scan_code_files(str(root))}


def _classify(name: str, body: str) -> bool:
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
        clear_caches()
        return is_minified_content(p)


class TestThresholdSanity:
    def test_fixture_line_is_over_the_threshold(self):
        assert len(CHUNK_LINE) > _MINIFIED_LINE_CHARS, \
            "the synthetic chunk must actually exceed the classifier threshold"

    def test_threshold_is_far_above_hand_written_lines(self):
        # 2000 chars is >3x the 600-char line the signature detector already
        # treats as pathological, so no ordinary source line can reach it.
        assert _MINIFIED_LINE_CHARS >= 2000
        assert len(SRC_LINE) < 200


class TestHashNamedChunksAreExcluded:
    def test_hash_named_chunk_is_not_scanned(self):
        got = _scanned({
            "src/app.ts": SRC_LINE + "\n",
            "public/assets/index-eq0Dxw.js": CHUNK_LINE + "\n",
            "public/assets/chunks/613-32d22f8f0887d915.js": CHUNK_LINE + "\n",
        })
        assert got == {"app.ts"}, f"hash-named chunks must be excluded; got {got}"

    def test_multi_line_bundle_with_a_banner_is_excluded(self):
        # Real chunks are not always a single line: a license banner, a
        # "use strict" prologue and a sourcemap comment surround the payload.
        body = (
            "/*! generated bundle - do not edit */\n"
            '"use strict";\n'
            + CHUNK_LINE + "\n"
            + CHUNK_LINE + "\n"
            "//# sourceMappingURL=chunk.js.map\n"
        )
        assert _classify("chunks/9883.js", body), \
            "a banner and a sourcemap comment must not hide a bundle"

    def test_bundled_stylesheet_is_classified_but_hand_written_css_is_not(self):
        # NB: .css is outside the default extension set, so this asserts the
        # classifier directly — it is what the skills passing a CSS-inclusive
        # extension set will consult.
        packed = ".a{color:red}" * 300
        assert len(packed) > _MINIFIED_LINE_CHARS
        assert _classify("app-9f2b1c.css", packed), "packed CSS is generated output"
        assert not _classify("theme.css", "body {\n  color: red;\n}\n")


class TestLegitimateSourceIsKept:
    def test_one_embedded_blob_does_not_condemn_a_file(self):
        # A single inlined data URI in an otherwise normal file: the long line
        # is a minority of the file's characters, so the file stays.
        blob = "const ICON = 'data:image/png;base64," + ("A" * 4000) + "';"
        body = "\n".join([SRC_LINE] * 200 + [blob] + [SRC_LINE] * 200) + "\n"
        assert not _classify("src/icons.ts", body), \
            "one embedded blob among real code is still source"

    def test_file_of_ordinary_lines_is_kept(self):
        body = "\n".join([SRC_LINE] * 500) + "\n"
        assert not _classify("src/routes.js", body)

    def test_empty_and_whitespace_files_are_kept(self):
        assert not _classify("src/empty.ts", "")
        assert not _classify("src/blank.ts", "\n\n\n")

    def test_char_fraction_boundary_is_a_majority_rule(self):
        # Just under the fraction -> kept. The padding is ordinary code, so the
        # decision turns on how much of the file the long line represents.
        pad = "x" * (int(len(CHUNK_LINE) / _MINIFIED_CHAR_FRACTION) - len(CHUNK_LINE) + 100)
        body = CHUNK_LINE + "\n" + "\n".join(pad[i:i + 60] for i in range(0, len(pad), 60))
        assert not _classify("src/wide.js", body), \
            "long line below the majority share must not exclude the file"


class TestNonBundlerFormatsAreNotClassified:
    def test_prose_and_data_formats_keep_their_long_lines(self):
        long_row = "INSERT INTO t VALUES (" + "1," * 2000 + "1);"
        for name in ("notes.md", "seed.sql", "openapi.yaml", "fixture.json"):
            assert not _classify(name, long_row + "\n"), \
                f"{name} may legitimately hold a long line and must stay scannable"

    def test_long_line_sql_is_still_enumerated(self):
        got = _scanned({"migrations/seed.sql": "INSERT INTO t VALUES (" + "1," * 2000 + "1);\n"})
        assert got == {"seed.sql"}


class TestOptInRestoresCoverage:
    def test_scan_minified_env_includes_content_matched_bundles(self):
        os.environ["VULTURE_SCAN_MINIFIED"] = "true"
        try:
            got = _scanned({"src/app.ts": SRC_LINE + "\n", "public/index-eq0Dxw.js": CHUNK_LINE})
            assert got == {"app.ts", "index-eq0Dxw.js"}, \
                f"VULTURE_SCAN_MINIFIED=true must restore bundle coverage; got {got}"
        finally:
            del os.environ["VULTURE_SCAN_MINIFIED"]


class TestBackupCopiesResolveThroughTheMarker:
    def test_backup_of_a_chunk_is_classified_on_its_effective_suffix(self):
        assert _classify("index-eq0Dxw.js.bak", CHUNK_LINE + "\n"), \
            "a shadow copy of a bundle is still a bundle"
