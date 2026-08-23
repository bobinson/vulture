"""Feature 0070 P8 — input-validation reachability (group `inputval`).

Two reviewed items, both owned by ``input_validation_check.py``:

* **CWE-23** Relative path traversal through an *archive entry name*
  ("zip slip"). The destination path is built from a name that the archive
  — not the server — controls, so ``../`` inside the entry escapes the
  extraction root. Three gates keep it quiet: the file must use an archive
  library, the name must be an archive-entry accessor (or a variable bound
  from one in the same file), and no containment idiom may sit in the
  surrounding window. Without the archive gate this rule is indistinguishable
  from an ordinary ``readdir`` loop over a fixed directory, which is the
  measured false positive it must not produce.
* **CWE-73** External control of a file name or path: a *direct* request-data
  accessor passed into a path builder/resolver. Only direct accessors count —
  a variable indirection would collapse into the loose identifier list that
  CWE-22 already uses, and CWE-22's rows are the noise gauge here.

Row-stacking invariants asserted below (skill findings are not deduplicated
against each other): CWE-23 takes the line from CWE-22, and CWE-73 takes the
line from CWE-20. In both pairs the survivor is the actionable descendant.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.input_validation_check import check_input_validation


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_input_validation(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


# --------------------------------------------------------------------------
# CWE-23 — relative path traversal from an archive entry name
# --------------------------------------------------------------------------

_ZIP_SLIP_JS = """\
const unzipper = require('unzipper')
async function unpack (buffer) {
  const directory = await unzipper.Open.buffer(buffer)
  for (const entry of directory.files) {
    const fileName = entry.path
    await pipeline(entry.stream(), fs.createWriteStream('uploads/' + fileName))
  }
}
"""

_ZIP_SLIP_PY = """\
import tarfile

def unpack(archive, dest):
    tar = tarfile.open(archive)
    for member in tar.getmembers():
        target = os.path.join(dest, member.name)
        write_bytes(target, tar.extractfile(member).read())
"""

_ZIP_SLIP_JAVA = """\
ZipInputStream zis = new ZipInputStream(stream);
ZipEntry entry;
while ((entry = zis.getNextEntry()) != null) {
    File out = new File(destDir, entry.getName());
    copy(zis, out);
}
"""

_ZIP_SLIP_POSITIVES = {
    "js_stream_concat": ("unpack.js", _ZIP_SLIP_JS),
    "py_tar_member": ("unpack.py", _ZIP_SLIP_PY),
    "java_zip_entry": ("Unpack.java", _ZIP_SLIP_JAVA),
}

# Clean twins: the SMALLEST edit that makes the destination containable.
_ZIP_SLIP_CLEAN = {
    "js_prefix_checked": (
        "unpack.js",
        _ZIP_SLIP_JS.replace(
            "    const fileName = entry.path\n",
            "    const fileName = entry.path\n"
            "    if (!path.resolve('uploads', fileName)"
            ".startsWith(path.resolve('uploads'))) continue\n",
        ),
    ),
    "py_basename": (
        "unpack.py",
        _ZIP_SLIP_PY.replace("dest, member.name", "dest, os.path.basename(member.name)"),
    ),
    "java_canonical_prefix": (
        "Unpack.java",
        _ZIP_SLIP_JAVA.replace(
            "    copy(zis, out);\n",
            "    if (!out.getCanonicalPath().startsWith(root)) { throw new IOException(); }\n"
            "    copy(zis, out);\n",
        ),
    ),
}


def test_cwe23_archive_entry_name_positives():
    for label, (name, body) in _ZIP_SLIP_POSITIVES.items():
        rows = _of(_run({name: body}), "CWE-23")
        assert rows, f"CWE-23 missed {label}"


def test_cwe23_containment_twins_are_clean():
    for label, (name, body) in _ZIP_SLIP_CLEAN.items():
        rows = _of(_run({name: body}), "CWE-23")
        assert not rows, f"CWE-23 false positive on {label}: {rows}"


def test_cwe23_needs_an_archive_library():
    """A `readdir` loop over a fixed directory is the measured false positive.

    Identical line shape, no archive anywhere: the entry name is produced by
    the server, not by an attacker-supplied container.
    """
    body = (
        "const files = await readdir('assets/i18n/')\n"
        "for (const fileName of files) {\n"
        "  const content = await readFile('assets/i18n/' + fileName, 'utf-8')\n"
        "}\n"
    )
    assert not _of(_run({"languages.js": body}), "CWE-23")


def test_cwe23_takes_the_line_from_cwe22():
    """One row per line: the CWE-22 generalisation must not stack under it."""
    findings = _run({"unpack.js": _ZIP_SLIP_JS})
    slip = _of(findings, "CWE-23")
    assert slip
    lines = {f["line_start"] for f in slip}
    assert not [f for f in _of(findings, "CWE-22") if f["line_start"] in lines]


# --------------------------------------------------------------------------
# CWE-73 — external control of file name or path
# --------------------------------------------------------------------------

_EXT_PATH_POSITIVES = {
    "node_resolve_body": (
        "render.js",
        "function show (req, res) {\n"
        "  const layout = path.resolve(req.body.layout)\n"
        "  res.render(layout)\n"
        "}\n",
    ),
    "python_join_query": (
        "docs.py",
        "def show():\n"
        '    full = os.path.join(DOC_ROOT, request.args.get("doc"))\n'
        "    return send(full)\n",
    ),
    "go_join_query": (
        "docs.go",
        "func show(w http.ResponseWriter, r *http.Request) {\n"
        '\tp := filepath.Join(dir, r.URL.Query().Get("name"))\n'
        "\tserve(w, p)\n"
        "}\n",
    ),
}

# Clean twins: the untrusted component is reduced to a bare file name.
_EXT_PATH_CLEAN = {
    "node_basename": (
        "render.js",
        "function show (req, res) {\n"
        "  const layout = path.resolve('layouts', path.basename(req.body.layout))\n"
        "  res.render(layout)\n"
        "}\n",
    ),
    "python_basename": (
        "docs.py",
        "def show():\n"
        '    full = os.path.join(DOC_ROOT, os.path.basename(request.args.get("doc")))\n'
        "    return send(full)\n",
    ),
    "go_base": (
        "docs.go",
        "func show(w http.ResponseWriter, r *http.Request) {\n"
        '\tp := filepath.Join(dir, filepath.Base(r.URL.Query().Get("name")))\n'
        "\tserve(w, p)\n"
        "}\n",
    ),
}


def test_cwe73_external_path_positives():
    for label, (name, body) in _EXT_PATH_POSITIVES.items():
        rows = _of(_run({name: body}), "CWE-73")
        assert rows, f"CWE-73 missed {label}"


def test_cwe73_reduced_to_basename_twins_are_clean():
    for label, (name, body) in _EXT_PATH_CLEAN.items():
        rows = _of(_run({name: body}), "CWE-73")
        assert not rows, f"CWE-73 false positive on {label}: {rows}"


def test_cwe73_needs_a_direct_request_accessor():
    """A variable indirection is CWE-22's territory, not a CWE-73 row."""
    body = (
        "function show (req, res) {\n"
        "  const layout = pickLayout()\n"
        "  const p = path.resolve(layout)\n"
        "  res.render(p)\n"
        "}\n"
    )
    assert not _of(_run({"render.js": body}), "CWE-73")


def test_cwe73_takes_the_line_from_cwe20():
    """One row per line: the CWE-20 generalisation must not stack under it."""
    name, body = _EXT_PATH_POSITIVES["node_resolve_body"]
    findings = _run({name: body})
    rows = _of(findings, "CWE-73")
    assert rows
    lines = {f["line_start"] for f in rows}
    assert not [f for f in _of(findings, "CWE-20") if f["line_start"] in lines]


def test_cwe73_yields_to_an_existing_path_traversal_row():
    """CWE-22 and CWE-73 are not in an ancestor relation — only one may fire."""
    body = (
        "function read (req, res) {\n"
        "  return fs.readFile(path.join(BASE, req.query.file), cb)\n"
        "}\n"
    )
    findings = _run({"read.js": body})
    per_line = [f["category"] for f in findings if f["line_start"] == 2]
    assert per_line.count("CWE-73") + per_line.count("CWE-22") == 1
