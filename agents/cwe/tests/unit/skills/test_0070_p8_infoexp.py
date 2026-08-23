"""Feature 0070 P8 — information exposure: CWE-538.

CWE-538 (Insertion of Sensitive Information into Externally-Accessible File or
Directory) is reached by ONE predicate: a generated artefact — an access log, an
audit trail, a dump, an export — whose write DESTINATION resolves to a directory
the web server publishes.

Three shapes were built and measured before this one; all three are recorded
here because the negative results are the reason the shipped rule looks the way
it does.

* **Mount-anchored 538** ("this static mount publishes a directory named
  `logs`/`encryptionkeys`/`backups`"). Dropped. The deterministic signature tier
  already claims `serveIndex(` / `autoIndex: true` lines for CWE-548, and on the
  measurement trees every real instance of a published sensitive directory was
  spelled with `serveIndex` — so the rule was a second row for one weakness. The
  `express.static('logs')` remainder measured ZERO on both trees.
* **Public-bundle secret env var** (`NEXT_PUBLIC_*_SECRET`, `VITE_*_PRIVATE_KEY`
  …). Scored zero on both trees. A rule that fires nowhere is not a detector.
* **CWE-615, credential in a source-code comment.** Loose form measured 8 rows on
  the clean tree and 8 were false — documentation prose inside a comment that
  merely *mentions* `password = …`. Tightened to a commented-out assignment with
  a non-placeholder value it measured zero on both trees. Dropped either way.

The shipped rule requires three independent facts, and each test class below
pins one of them:

  1. the line is a write DESTINATION,
  2. the literal path's directory is a served root,
  3. the basename names a GENERATED artefact.

Fact 3 is load-bearing rather than decorative: without it, a stream writing an
uploaded attachment into `uploads/` and one writing a profile image into a built
frontend's asset directory were 2 of 4 measured rows, and both are the design of
the feature rather than a leak.

The predicate needs the served-root set, which is derived from mount
declarations ANYWHERE in the tree, so a positive fixture needs two files. The
corpus runner flattens each fixture to a single file, so only the
conventional-public-name half of fact 2 is corpus-gateable; that half is what
`tests/corpus/manifest.d/p8_infoexp.yaml` gates, and the declared-mount half is
unit-tested here.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills import SKILL_MAP
from cwe_agent.skills.info_exposure_check import (
    check_information_exposure,
    served_roots,
)

# A mount declaration that makes `logs/` externally reachable. Generic Express
# idiom; nothing about it is specific to any codebase.
_LOG_MOUNT = "app.use('/support', express.static('logs'))\n"


def _run(files: dict[str, str], skill=check_information_exposure) -> list[dict]:
    """Materialise `files` (path -> body) in a temp root and run one skill."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return skill(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


def _mounted(body: str, name: str = "logging.ts") -> list[dict]:
    """Run `body` in a tree whose `logs/` directory is a declared mount."""
    return _of(_run({"server.ts": _LOG_MOUNT, name: body}), "CWE-538")


# ---------------------------------------------------------------------------
# Fact 1 — the line must be a write destination
# ---------------------------------------------------------------------------
class TestDestinationEvidence:
    def test_rotating_log_transport(self):
        assert _mounted("const t = { filename: path.resolve('logs/access.log') }\n")

    def test_audit_file_key(self):
        assert _mounted("const t = { audit_file: 'logs/audit.json' }\n")

    def test_python_file_handler(self):
        found = _mounted(
            "h = logging.FileHandler('logs/debug.log')\n", name="app.py"
        )
        assert found

    def test_jvm_logging_config_attribute(self):
        """The key arm carries the XML dialects that quote their path."""
        found = _mounted(
            '  <RollingFile fileName="logs/application.log">\n',
            name="log4j2.xml",
        )
        assert found

    def test_unquoted_xml_element_text_is_a_known_blind_spot(self):
        """Documented, not accidental: the path extractor requires a quote.

        Claiming the element without teaching `_PATH_LITERAL` about element text
        would be an attestation the code cannot honour.
        """
        assert not _mounted(
            "  <file>logs/application.log</file>\n", name="logback.xml"
        )

    def test_a_path_that_is_only_read_is_not_reported(self):
        """Clean twin: same literal, no destination evidence on the line."""
        assert not _mounted("const raw = fs.readFileSync('logs/access.log')\n")

    def test_a_bare_mention_of_the_path_is_not_reported(self):
        assert not _mounted("const LOG_DOC_URL = 'logs/access.log'\n")

    def test_a_generic_write_sink_is_not_destination_evidence(self):
        """The deliberate blind spot, pinned so it is not "fixed" by accident.

        `createWriteStream` / `fs.writeFile*` / `os.WriteFile` / `open(…, 'w')`
        are the verbs the resource skill keys on for CWE-404 and CWE-379.
        Accepting them here puts a second row on lines that are already claimed,
        which is why only a configured DESTINATION counts.
        """
        assert not _mounted(
            "const s = fs.createWriteStream('logs/error.log')\n", name="stream.js"
        )


# ---------------------------------------------------------------------------
# Fact 2 — the directory must actually be served
# ---------------------------------------------------------------------------
class TestServedRootEvidence:
    def test_declared_mount_makes_the_directory_served(self):
        assert _mounted("const t = { filename: 'logs/access.log' }\n")

    def test_conventional_public_name_needs_no_declaration(self):
        found = _of(
            _run({"logging.js": "const t = { filename: 'public/access.log' }\n"}),
            "CWE-538",
        )
        assert found

    def test_unserved_directory_is_clean(self):
        """Clean twin: identical write, no mount anywhere and a private dir."""
        found = _of(
            _run({"logging.ts": "const t = { filename: 'var/log/access.log' }\n"}),
            "CWE-538",
        )
        assert not found

    def test_absolute_system_path_is_clean(self):
        found = _of(
            _run({"logging.ts": "const t = { filename: '/var/log/app/access.log' }\n"}),
            "CWE-538",
        )
        assert not found

    def test_bare_filename_without_a_directory_is_clean(self):
        """No directory component means nothing to resolve against a root."""
        assert not _mounted("const t = { filename: 'access.log' }\n")


# ---------------------------------------------------------------------------
# Fact 3 — the basename must name a generated artefact
# ---------------------------------------------------------------------------
class TestGeneratedArtefactEvidence:
    def test_user_content_destination_in_a_public_directory_is_clean(self):
        """The measured false-positive class, pinned.

        Landing user content in a served directory is the feature, not a leak.
        A predicate that keys only on `destination + served root` reports it.
        """
        found = _of(
            _run({"upload.js": "const opts = { filename: 'public/images/' + name }\n"}),
            "CWE-538",
        )
        assert not found

    def test_non_artefact_basename_in_a_served_root_is_clean(self):
        found = _of(
            _run({"brand.js": "const opts = { filename: 'public/logo.png' }\n"}),
            "CWE-538",
        )
        assert not found

    def test_interpolated_artefact_name_still_reports(self):
        assert _mounted("const t = { filename: `logs/${day}.log` }\n")


# ---------------------------------------------------------------------------
# Guards shared with the rest of the skill
# ---------------------------------------------------------------------------
class TestGuards:
    def test_prose_file_describing_the_mistake_is_not_reported(self):
        found = _of(
            _run({
                "server.ts": _LOG_MOUNT,
                "hardening.md": "Never set `filename: 'logs/access.log'` here.\n",
            }),
            "CWE-538",
        )
        assert not found

    def test_commented_out_destination_is_not_reported(self):
        assert not _mounted("// const t = { filename: 'logs/access.log' }\n")

    def test_finding_is_anchored_on_the_destination_line(self):
        found = _mounted(
            "const a = 1\nconst b = 2\nconst t = { filename: 'logs/access.log' }\n"
        )
        assert found and found[0]["line_start"] == 3


# ---------------------------------------------------------------------------
# Disjointness: one weakness, one row
# ---------------------------------------------------------------------------
class TestNoRowStacking:
    def test_destination_line_carries_exactly_one_row(self):
        """Checked across the WHOLE deterministic stack, not just this skill.

        Skill findings are never deduplicated against each other, so a sibling
        that also claimed the line would ship two rows for one weakness. This is
        the assertion that caught the mount-anchored design colliding with the
        CWE-548 directory-listing signature.
        """
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "server.ts").write_text(_LOG_MOUNT)
            (Path(d) / "logging.ts").write_text(
                "const t = { filename: 'logs/access.log' }\n"
            )
            rows = [
                f
                for fn in SKILL_MAP.values()
                for f in fn(d)["findings"]
                if Path(f.get("file_path", "")).name == "logging.ts"
            ]
        assert len(rows) == 1, f"expected one row on the destination line, got {rows}"
        assert rows[0]["category"] == "CWE-538"

    def test_pre_existing_313_detector_is_untouched(self):
        """The neighbouring rule must keep firing on its own shape.

        CWE-538 no longer accepts a generic write sink as evidence, so the two
        predicates are disjoint by construction rather than by precedence — this
        pins that the narrowing did not cost CWE-313 its line.
        """
        findings = _run({
            "backup.js": (
                "fs.writeFileSync('/etc/app/creds', `password=${dbPassword}`)\n"
            ),
        })
        assert _of(findings, "CWE-313")
        assert not _of(findings, "CWE-538")


# ---------------------------------------------------------------------------
# The mount table is shared, so widening it must also widen the resolver
# ---------------------------------------------------------------------------
class TestSharedMountTable:
    def test_resolver_learns_the_new_framework_idioms(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "main.py").write_text(
                'app.mount("/x", StaticFiles(directory="reports"), name="x")\n'
            )
            (root / "srv.go").write_text('http.FileServer(http.Dir("./exports"))\n')
            roots = served_roots(str(root))
        assert "reports" in roots, "a Python static mount must be resolved"
        assert "exports" in roots, "a Go static mount must be resolved"
        assert "public" in roots, "the fallback name list must still apply"

    def test_joined_path_mount_is_resolved(self):
        """`express.static(path.join(__dirname, 'x'))` is the common spelling."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "server.js").write_text(
                "app.use(express.static(path.join(__dirname, 'vaultfiles')))\n"
            )
            roots = served_roots(str(root))
        assert "vaultfiles" in roots

    def test_relative_prefix_is_normalised(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "server.js").write_text("express.static('./customdir')\n")
            roots = served_roots(str(root))
        assert "customdir" in roots, "'./' must not survive into the root name"

    def test_dotted_directory_keeps_its_leading_dot(self):
        """`lstrip('./')` would eat the dot of `.git` — the worst case to miss."""
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "server.js").write_text("express.static('.well-known')\n")
            roots = served_roots(str(root))
        assert ".well-known" in roots
