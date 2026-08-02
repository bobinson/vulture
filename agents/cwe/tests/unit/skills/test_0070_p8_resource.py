"""Feature 0070 P8 — resource detection group.

One new detector: **CWE-379** (creation of a temporary file or directory at a
PREDICTABLE path inside a shared, world-writable temp directory).

The weakness is not "a temp file exists" — it is that the path is guessable
*and* the containing directory is writable by every local account, so another
user can pre-create, symlink or read it before the owner does. Two idioms
express that, and both are content-keyed (no filename/layout dependency):

  arm 1  a FIXED name joined onto the platform temp-dir accessor
         (``filepath.Join(os.TempDir(), "app-cache")``)
  arm 2  a hardcoded ``/tmp``-family literal handed to a create/write sink
         (``open('/tmp/app-export.csv', 'w')``)

Every secure-temp API (``os.MkdirTemp``, ``mkdtemp``, ``mkstemp``,
``NamedTemporaryFile``, ``fs.mkdtemp``…) generates an unpredictable name in a
0700 directory, so its presence on the line clears both arms — that is the
clean twin of each positive. So does any randomiser in the name.

Row-stacking invariant (rule 6): CWE-404 (improper shutdown) matches the same
``open(`` / ``fs.create*`` verbs that arm 2 keys on. CWE-379 is NOT a catalog
descendant of CWE-404, so emitting both would be a duplicate row. CWE-379
claims the line and CWE-404 is suppressed there; asserted below.
"""

from cwe_agent.skills.resource_check import check_resource_management


def _findings(path) -> list[dict]:
    return check_resource_management(str(path))["findings"]


def _cats(path) -> list[str]:
    return [f["category"] for f in _findings(path)]


def _of(path, category: str) -> list[dict]:
    return [f for f in _findings(path) if f["category"] == category]


# ── arm 1: fixed name joined onto the platform temp root ──────────────
class TestPredictableNameInSharedTemp:
    def test_go_filepath_join_tempdir_literal_fires(self, tmp_path):
        (tmp_path / "known_hosts.go").write_text(
            "func defaultPath() string {\n"
            "\tdir := filepath.Join(os.TempDir(), \"app-ssh\")\n"
            "\t_ = os.MkdirAll(dir, 0o700)\n"
            "\treturn dir\n"
            "}\n"
        )
        rows = _of(tmp_path, "CWE-379")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 2
        assert rows[0]["check_id"] == "cwe.resource.insecure_temp_dir"

    def test_node_path_join_tmpdir_literal_fires(self, tmp_path):
        (tmp_path / "store.ts").write_text(
            "export function storeDir () {\n"
            "  return path.join(os.tmpdir(), 'session-store')\n"
            "}\n"
        )
        assert "CWE-379" in _cats(tmp_path)

    def test_python_ospath_join_gettempdir_fires(self, tmp_path):
        (tmp_path / "cache.py").write_text(
            "import os\n"
            "import tempfile\n"
            "\n"
            "def cache_dir():\n"
            "    return os.path.join(tempfile.gettempdir(), 'app-cache')\n"
        )
        assert "CWE-379" in _cats(tmp_path)

    def test_string_concat_form_fires(self, tmp_path):
        (tmp_path / "store.js").write_text(
            "function target () {\n"
            "  return os.tmpdir() + '/app-report.pdf'\n"
            "}\n"
        )
        assert "CWE-379" in _cats(tmp_path)

    def test_java_tmpdir_property_fires(self, tmp_path):
        (tmp_path / "Cache.java").write_text(
            "class Cache {\n"
            "  String dir() {\n"
            "    return Paths.get(System.getProperty(\"java.io.tmpdir\"), \"app-cache\").toString();\n"
            "  }\n"
            "}\n"
        )
        assert "CWE-379" in _cats(tmp_path)

    # --- clean twins ---------------------------------------------------

    def test_secure_mkdirtemp_clean(self, tmp_path):
        """One-token twin of the Go positive: the secure API randomises."""
        (tmp_path / "known_hosts.go").write_text(
            "func defaultPath() (string, error) {\n"
            "\tdir, err := os.MkdirTemp(os.TempDir(), \"app-ssh-\")\n"
            "\treturn dir, err\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_secure_mkdtemp_clean(self, tmp_path):
        (tmp_path / "store.ts").write_text(
            "export function storeDir () {\n"
            "  return fs.mkdtempSync(path.join(os.tmpdir(), 'session-'))\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_randomised_name_clean(self, tmp_path):
        (tmp_path / "store.js").write_text(
            "function target () {\n"
            "  return path.join(os.tmpdir(), 'app-' + randomUUID())\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_formatted_name_is_not_a_fixed_literal(self, tmp_path):
        """`%d` is a placeholder — the resulting name is not predictable."""
        (tmp_path / "run.go").write_text(
            "func runDir(pid int) string {\n"
            "\treturn filepath.Join(os.TempDir(), fmt.Sprintf(\"run-%d\", pid))\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_temp_root_without_join_clean(self, tmp_path):
        """A bare read of the temp root is not a creation site."""
        (tmp_path / "list.js").write_text(
            "function listing () {\n"
            "  return fs.readdirSync(os.tmpdir(), 'utf8')\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_non_temp_base_clean(self, tmp_path):
        (tmp_path / "cache.py").write_text(
            "import os\n"
            "\n"
            "def cache_dir(base):\n"
            "    return os.path.join(base, 'app-cache')\n"
        )
        assert "CWE-379" not in _cats(tmp_path)


# ── arm 2: hardcoded /tmp-family literal handed to a create/write sink ─
class TestHardcodedSharedTempLiteral:
    def test_python_open_write_fires(self, tmp_path):
        (tmp_path / "export.py").write_text(
            "def dump(rows):\n"
            "    with open('/tmp/app-export.csv', 'w') as fh:\n"
            "        fh.write(rows)\n"
        )
        rows = _of(tmp_path, "CWE-379")
        assert len(rows) == 1
        assert rows[0]["line_start"] == 2

    def test_c_fopen_fires(self, tmp_path):
        (tmp_path / "dump.c").write_text(
            "int dump(void) {\n"
            "  FILE *f = fopen(\"/var/tmp/app.log\", \"w\");\n"
            "  fclose(f);\n"
            "  return 0;\n"
            "}\n"
        )
        assert "CWE-379" in _cats(tmp_path)

    def test_node_write_file_sync_fires(self, tmp_path):
        (tmp_path / "audit.js").write_text(
            "function persist (data) {\n"
            "  fs.writeFileSync('/dev/shm/app-state.json', data)\n"
            "}\n"
        )
        assert "CWE-379" in _cats(tmp_path)

    # --- clean twins ---------------------------------------------------

    def test_secure_tempfile_clean(self, tmp_path):
        (tmp_path / "export.py").write_text(
            "import os\n"
            "import tempfile\n"
            "\n"
            "def dump(rows):\n"
            "    with open(os.path.join(tempfile.mkdtemp(), 'app-export.csv'), 'w') as fh:\n"
            "        fh.write(rows)\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_private_directory_clean(self, tmp_path):
        (tmp_path / "audit.js").write_text(
            "function persist (data) {\n"
            "  fs.writeFileSync('/var/lib/app/state.json', data)\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_temp_literal_without_sink_clean(self, tmp_path):
        """A constant is not a creation site; the write may be guarded."""
        (tmp_path / "paths.go").write_text(
            "package app\n"
            "\n"
            "const DefaultCacheDir = \"/tmp/app-cache\"\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_bare_tmp_root_literal_clean(self, tmp_path):
        """`/tmp` with no child component names the directory, not a file."""
        (tmp_path / "probe.js").write_text(
            "function probe () {\n"
            "  fs.accessSync('/tmp', fs.constants.W_OK)\n"
            "}\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_temp_path_inside_a_message_clean(self, tmp_path):
        """The literal has to BE the path, not mention one in prose."""
        (tmp_path / "log.py").write_text(
            "def warn(log):\n"
            "    log.error('unable to open /tmp/app-cache for writing')\n"
        )
        assert "CWE-379" not in _cats(tmp_path)


# ── rule 6: one row per line ──────────────────────────────────────────
class TestNoRowStacking:
    def test_379_suppresses_the_404_row_on_the_same_line(self, tmp_path):
        """`open('/tmp/x','w')` matches CWE-404's verb too — one row only."""
        (tmp_path / "export.py").write_text(
            "def dump(rows):\n"
            "    fh = open('/tmp/app-export.csv', 'w')\n"
            "    fh.write(rows)\n"
        )
        cats = _cats(tmp_path)
        assert cats.count("CWE-379") == 1
        assert "CWE-404" not in cats

    def test_404_still_fires_on_a_non_temp_open(self, tmp_path):
        """No over-correction: the CWE-404 arm is untouched elsewhere."""
        (tmp_path / "reader.py").write_text(
            "handle = open('announcement.md', 'r')\n"
            "data = handle.read()\n"
        )
        assert "CWE-404" in _cats(tmp_path)

    def test_one_row_per_matching_line(self, tmp_path):
        (tmp_path / "paths.go").write_text(
            "func a() string { return filepath.Join(os.TempDir(), \"app-a\") }\n"
            "func b() string { return filepath.Join(os.TempDir(), \"app-b\") }\n"
        )
        rows = _of(tmp_path, "CWE-379")
        assert [r["line_start"] for r in rows] == [1, 2]


# ── guards ────────────────────────────────────────────────────────────
class TestGuards:
    def test_prose_file_is_not_scanned(self, tmp_path):
        (tmp_path / "TEMPFILES.md").write_text(
            "# Temp file policy\n"
            "\n"
            "Never do this:\n"
            "\n"
            "    open('/tmp/app-export.csv', 'w')\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_commented_line_is_not_scanned(self, tmp_path):
        (tmp_path / "cache.go").write_text(
            "package app\n"
            "\n"
            "// dir := filepath.Join(os.TempDir(), \"app-cache\")\n"
            "func dir() string { return cfg.Dir }\n"
        )
        assert "CWE-379" not in _cats(tmp_path)

    def test_existing_799_guard_still_holds(self, tmp_path):
        """CWE-799 must keep firing — nothing in P8 may narrow it."""
        (tmp_path / "server.ts").write_text(
            "  app.post('/rest/user/login', login())\n"
        )
        assert "CWE-799" in _cats(tmp_path)
