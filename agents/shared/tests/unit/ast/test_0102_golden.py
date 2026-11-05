"""Feature 0102 (LLD D14, §6.4, §16 risk 18): golden structural hashes.

Each v1 profile carries a small set of golden INPUTS (below) and, for each, a
golden DIGEST in ``_golden/<language>/<input name>.sha256``: the sha256 of the
canonical structure of the ``FileModel`` that ``shared.ast.get_model`` builds
for that input through a REAL worker and the real grammar. A grammar bump, a
``NODE_MAP`` edit or a worker/validator change that alters what the analysis
sees changes a digest and fails here, so the change lands as a reviewed diff
of the goldens (LLD §14 "goldens as a reviewed diff") instead of silently
moving every finding. For C/C++ the goldens are one of the two bounds on a
systematic silent misparse (§16 risk 18).

The digest is STRUCTURAL: per node its kind, parent, field, byte span,
newline-only line, identifier text and (for a LITERAL) its admitted value,
plus the file's language, size, error count and unmapped tally. It excludes
the grammar version string (pinned by ``test_0102_grammar_versions.py``) and
everything a model never carries: comment text and literal content (D16), so
a same-length edit of either leaves the digest unchanged while a renamed
identifier or a shifted byte changes it.

Inputs per profile: ``constructs`` (ordinary code, parses clean),
``syntax_error`` (one ERROR node between valid statements: the partial
structure a decoy syntax error leaves, T7), ``hostile`` (a UTF-8 BOM, CRLF on
disk, U+2028/U+2029/VT/FF/NEL inside a literal and a comment, 2- and 4-byte
characters and one invalid UTF-8 byte: spans are byte offsets into the
parent's re-encoded text and lines count ``\\n`` only — T5, T14, D21), and for
TypeScript a ``.tsx`` file whose JSX parses only under ``language_tsx``
(§6.3). Every input's declared parse outcome is first checked against the
grammar the LLD names, in this process, so no golden can enshrine a misparse.

GENERATION. ``scripts/regen-ast-goldens.py`` writes each input's
``structural_digest(model_for(...))`` into ``_golden/`` (and removes any golden
that has no input): this module is the ONE definition of the inputs and of the
digest (D19). A missing golden
fails with the regeneration command; regenerate, then review the diff.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

import pytest
import tree_sitter

from shared.ast import FileModel, get_model, owns
from shared.ast.kinds import Field, Kind
from shared.ast.pool import reset_pool_for_tests
from shared.ast.profile import PROFILES
from shared.tools.file_scanner import read_file_safe
from tests.unit.ast._support import GRAMMARS, LANGUAGES, TSX_GRAMMAR, grammar, write

# One W = 1 real-worker pool for the module (``conftest.py``); a fresh context on entry.
pytestmark = pytest.mark.usefixtures("real_pool")

GOLDEN_DIR = Path(__file__).resolve().parent / "_golden"
REGEN_COMMAND = "scripts/regen-ast-goldens.py"

# The nine v1 profiles (D-D, D-H), keyed by `shared.language` names.
V1_LANGUAGES = tuple(sorted(LANGUAGES))

_DIGEST_FORMAT = re.compile(rb"[0-9a-f]{64}\n?")


@dataclass(frozen=True)
class GoldenCase:
    """One golden input: the file written to disk and its declared parse."""

    language: str
    name: str
    source: bytes
    clean: bool

    @property
    def golden(self) -> Path:
        """Where this input's digest lives."""
        return GOLDEN_DIR / self.language / f"{self.name}.sha256"

    @property
    def case_id(self) -> str:
        """``language/name``, the pytest id."""
        return f"{self.language}/{self.name}"


# ── hostile bytes (T5, T14, D21) ──────────────────────────────────────────────
# U+2028/U+2029, VT, FF and NEL split a `str.splitlines()` line but are not
# newlines to tree-sitter; U+00E9 is 2 bytes and the emoji 4, so byte and character
# offsets diverge after them. On disk the file also starts with a BOM, uses CRLF
# and carries one invalid UTF-8 byte inside the literal: `read_file_safe` keeps
# the BOM as U+FEFF, folds CRLF to LF and decodes the byte to U+FFFD (3 bytes),
# so the model's size and spans must follow the parent's re-encoded text (§4).
HOSTILE_LITERAL = "a\u2028b\u2029c\x0bd\x0ce\x85f \u00e9 \U0001f600 "
HOSTILE_COMMENT = "note \u2028 \u2029 \x0c \u00e9 \U0001f600 end"
_BOM = b"\xef\xbb\xbf"
_INVALID_UTF8 = b"\xff"


def hostile_bytes(
    template: str, *, literal: str = HOSTILE_LITERAL, comment: str = HOSTILE_COMMENT
) -> bytes:
    """Render a hostile template: ``@C@`` comment, ``@S@`` literal, ``@X@`` bad byte."""
    text = template.replace("@C@", comment).replace("@S@", literal).replace("\n", "\r\n")
    return _BOM + text.encode("utf-8").replace(b"@X@", _INVALID_UTF8)


# ── golden inputs ─────────────────────────────────────────────────────────────

_JS = """\
// Golden input (feature 0102): ordinary JavaScript shapes.
const fs = require("fs");
import { join as joinPath } from "path";

class Store {
  constructor(root) {
    this.root = root;
  }
}

export async function handler(req, res, { limit = 10, ...rest }) {
  let target = req.query.file;
  const parts = [target, "x", 42, true, null, ...rest.more];
  if (!target || typeof target !== "string") {
    return res.status(400).send(`missing ${target}`);
  } else if (parts.length > limit && /^[a-z]+$/.test(target)) {
    throw new Error("too many");
  }
  for (const part of parts) {
    target += part;
  }
  switch (rest.mode) {
    case "a":
      target = joinPath(new Store("/srv").root, target);
      break;
    default:
      target = undefined;
  }
  try {
    await fs.promises.readFile(target);
    fs.readFile(target, (err, data) => res.send(err ? null : data));
  } catch (e) {
    console.error(e);
  } finally {
    res.end();
  }
  return rest?.["key"] ?? rest[0];
}
"""

_JS_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
const before = 1;
function broken(a) {
  return a ) ) ;
}
const after = broken(before);
"""

_JS_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
/* @C@ */
const label = "@S@@X@";
fs.readFile(label);
"""

_TS = """\
// Golden input (feature 0102): ordinary TypeScript shapes.
import { readFile } from "fs/promises";
import type { Incoming } from "./types";

enum Mode { Read = 1, Write }

interface Options<T> { limit?: number; extra: T }

@Route("files")
export class FileController<T> {
  constructor(private readonly root: string) {}

  @Get(":name")
  async fetch(@Param("name") name: string, opts?: Options<T>, req?: Incoming): Promise<string> {
    const target = (opts as Options<T>).extra ?? name;
    const width = <number>(opts ? 1 : 0);
    const list: Array<string> = [target, String(width), String(Mode.Read)];
    if (typeof target !== "string") {
      throw new Error("bad");
    }
    for (const item of list) {
      await readFile(`${this.root}/${item}`);
    }
    return list.map((x: string): string => x.trim())[0]!;
  }
}
"""

_TSX = """\
// Golden input (feature 0102): JSX in a .tsx file parses only under language_tsx.
import { useValue } from "./state";

export function Viewer(props: { file: string }) {
  const [name, setName] = useValue<string>(props.file);
  return (
    <div className="viewer" onClick={() => setName(name + "!")}>
      {name.length > 0 ? <span>{name}</span> : null}
    </div>
  );
}
"""

_TS_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
const before: number = 1;
function broken(a: number) {
  return a ) ) ;
}
const after = broken(before);
"""

_TS_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
/* @C@ */
const label: string = "@S@@X@";
readFile(label);
"""

_PY = """\
# Golden input (feature 0102): ordinary Python shapes.
import os
import subprocess as sp
from os import path as osp

COUNT = 0


def logged(fn):
    return fn


@logged
def handler(request, limit: int = 10, *args, **kwargs):
    global COUNT
    target = request.args["file"]
    parts = [target, "x", 42, True, None]
    if not target:
        return None
    elif len(parts) > limit:
        raise ValueError(f"too many {target}")
    for part in parts:
        target += str(part)
    match kwargs.get("mode"):
        case "a":
            target = osp.join("/srv", target)
        case _:
            target = None
    try:
        with open(target) as fh:
            data = fh.read()
    except OSError as exc:
        data = str(exc)
    finally:
        COUNT += 1
    names = [n for n in os.listdir(".") if n]
    sp.run(["ls", "-l", target], shell=True, check=False)
    return lambda: (data, names)
"""

_PY_ERROR = """\
# Golden input (feature 0102): a syntax error between two valid statements.
before = 1
def broken(a):
    return a ) )

after = broken(before)
"""

_PY_HOSTILE = """\
# Golden input (feature 0102): hostile bytes and line terminators.
# @C@
label = "@S@@X@"
open(label)
"""

_GO = """\
// Golden input (feature 0102): ordinary Go shapes.
package main

import (
\t"net/http"
\t"os"
\t"os/exec"
)

type Form struct{ Path string }

func handler(w http.ResponseWriter, r *http.Request) {
\ttarget := r.URL.Query().Get("file")
\tparts := []string{target, "x"}
\tvar form Form
\tif err := decode(r, &form); err != nil {
\t\thttp.Error(w, err.Error(), 400)
\t\treturn
\t}
\tfor i, part := range parts {
\t\ttarget += part + string(rune(i))
\t}
\tswitch form.Path {
\tcase "a":
\t\ttarget = "/srv/" + target
\tdefault:
\t\ttarget = ""
\t}
\tdata, err := os.ReadFile(target)
\tif err != nil {
\t\tpanic(err)
\t}
\tdefer w.Write(data)
\tgo exec.Command("ls", "-l", target).Run()
}
"""

_GO_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
package main

var before = 1

func broken(a int) int {
\treturn a ) )
}

var after = broken(before)
"""

_GO_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
package main

/* @C@ */
var label = "@S@@X@"

func use() { open(label) }
"""

_JAVA = """\
// Golden input (feature 0102): ordinary Java shapes.
package demo;

import java.io.File;
import java.nio.file.Paths;
import java.util.List;

@Route("/files")
public class FileHandler {
    private final String root = "/srv";

    @Get("/files")
    public String fetch(@Param("name") String name, List<String> extra) throws Exception {
        String target = name;
        if (target == null || target.isEmpty()) {
            return "";
        }
        for (String part : extra) {
            target += part;
        }
        switch (target.length()) {
            case 0 -> target = root;
            default -> target = target.trim();
        }
        try {
            File file = new File(root, target);
            return Paths.get(file.getPath()).toString();
        } catch (IllegalArgumentException e) {
            throw new RuntimeException(e);
        } finally {
            extra.forEach(x -> System.out.println(x));
        }
    }
}
"""

_JAVA_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
class Broken {
    int before = 1;
    int broken(int a) {
        return a ) ) ;
    }
    int after = broken(before);
}
"""

_JAVA_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
class Hostile {
    /* @C@ */
    String label = "@S@@X@";
    void use() { open(label); }
}
"""

_RUST = """\
// Golden input (feature 0102): ordinary Rust shapes.
use std::fs;
use std::process::Command;

struct Form {
    path: String,
}

fn handler(form: &Form, extra: Vec<String>) -> Result<String, std::io::Error> {
    let mut target = form.path.clone();
    if target.is_empty() {
        return Ok(String::new());
    }
    for part in extra.iter() {
        target.push_str(part);
    }
    match target.len() {
        0 => target = "/srv".to_string(),
        n if n > 10 => target.truncate(10),
        _ => {}
    }
    let data = fs::read_to_string(&target)?;
    let out = Command::new("ls").arg("-l").arg(&target).output()?;
    println!("{} {}", data, out.status);
    let close = |x: &str| x.len();
    Ok(format!("{}", close(&data)))
}
"""

_RUST_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
const BEFORE: i32 = 1;
fn broken(a: i32) -> i32 {
    a ) )
}
fn after() -> i32 { broken(BEFORE) }
"""

_RUST_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
fn use_label() {
    /* @C@ */
    let label = "@S@@X@";
    open(label);
}
"""

_PHP = r"""<html><body>
<?php
// Golden input (feature 0102): ordinary PHP shapes inside a template.
namespace Demo;

use Some\Thing as Other;

function handler(array $opts = []): string
{
    $target = $_GET['file'] ?? '';
    $parts = [$target, "x", 42, TRUE, null];
    if (!$target) {
        return "";
    } elseif (count($parts) > 10) {
        throw new \Exception("too many {$target}");
    }
    foreach ($parts as $key => $part) {
        $target .= $part;
    }
    switch ($opts['mode'] ?? '') {
        case 'a':
            $target = '/srv/' . $target;
            break;
        default:
            $target = match (strlen($target)) { 0 => 'x', default => $target };
    }
    try {
        include $target;
        $out = `ls -l $target`;
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $target);
        \Demo\helper($out);
    } catch (\Exception $e) {
        echo $e->getMessage();
    } finally {
        $opts = null;
    }
    return file_get_contents($target);
}
?>
<p>done</p>
</body></html>
"""

_PHP_ERROR = """\
<?php
// Golden input (feature 0102): a syntax error between two valid statements.
$before = 1;
function broken($a) {
    return $a ) ) ;
}
$after = broken($before);
"""

_PHP_HOSTILE = """\
<?php
// Golden input (feature 0102): hostile bytes and line terminators.
/* @C@ */
$label = "@S@@X@";
fopen($label, 'r');
"""

_C = """\
// Golden input (feature 0102): ordinary C shapes.
#include <stdio.h>
#include <stdlib.h>
#define LIMIT 10

struct form { char *path; };

static int count;

int main(int argc, char **argv) {
    char *p = argv[1];
    char buf[64];
    struct form f = { p };
    if (argc < 2) {
        return 1;
    }
    for (int i = 0; i < LIMIT; i++) {
        count += i;
    }
    switch (argc) {
    case 2:
        p = f.path;
        break;
    default:
        p = NULL;
    }
    FILE *fp = fopen(p, "r");
    while (fgets(buf, sizeof buf, fp) != NULL) {
        printf("%s", buf);
    }
    snprintf(buf, sizeof(buf), "ls %s", p);
    system(buf);
    return fp == NULL ? 2 : 0;
}
"""

_C_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
int before = 1;
int broken(int a) {
    return a ) ) ;
}
int after(void) { return broken(before); }
"""

_C_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
#include <stdio.h>
/* @C@ */
static const char *label = "@S@@X@";
void use(void) { fopen(label, "r"); }
"""

_CPP = """\
// Golden input (feature 0102): ordinary C++ shapes.
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace demo {

class Reader {
public:
    explicit Reader(std::string root) : root_(std::move(root)) {}
    std::string read(const std::string &name) const;
private:
    std::string root_;
};

std::string Reader::read(const std::string &name) const {
    std::string target = root_ + "/" + name;
    std::vector<std::string> parts{target, "x"};
    std::string &ref = target;
    for (const auto &part : parts) {
        ref += part;
    }
    std::ifstream in(target);
    try {
        std::system(("ls -l " + target).c_str());
    } catch (const std::exception &e) {
        return e.what();
    }
    auto close = [&](int x) { return parts[x]; };
    return close(0);
}

}  // namespace demo

int main(int argc, char *argv[]) {
    switch (argc) {
    case 1:
        return 1;
    default:
        break;
    }
    demo::Reader reader(argv[1]);
    return reader.read(argv[2]).empty() ? 1 : 0;
}
"""

_CPP_ERROR = """\
// Golden input (feature 0102): a syntax error between two valid statements.
int before = 1;
int broken(int a) {
    return a ) ) ;
}
int after() { return broken(before); }
"""

_CPP_HOSTILE = """\
// Golden input (feature 0102): hostile bytes and line terminators.
#include <cstdio>
/* @C@ */
static const char *label = "@S@@X@";
void use() { std::fopen(label, "r"); }
"""

# language -> (hostile file name, template); every template names one
# identifier `label` and one literal, so the mutation test can edit either.
HOSTILE_TEMPLATES: dict[str, tuple[str, str]] = {
    "c": ("hostile.c", _C_HOSTILE),
    "cpp": ("hostile.cpp", _CPP_HOSTILE),
    "go": ("hostile.go", _GO_HOSTILE),
    "java": ("hostile.java", _JAVA_HOSTILE),
    "javascript": ("hostile.js", _JS_HOSTILE),
    "php": ("hostile.php", _PHP_HOSTILE),
    "python": ("hostile.py", _PY_HOSTILE),
    "rust": ("hostile.rs", _RUST_HOSTILE),
    "typescript": ("hostile.ts", _TS_HOSTILE),
}

# language -> (constructs file, source, syntax-error file, source)
_PLAIN: dict[str, tuple[str, str, str, str]] = {
    "c": ("constructs.c", _C, "syntax_error.c", _C_ERROR),
    "cpp": ("constructs.cpp", _CPP, "syntax_error.cpp", _CPP_ERROR),
    "go": ("constructs.go", _GO, "syntax_error.go", _GO_ERROR),
    "java": ("constructs.java", _JAVA, "syntax_error.java", _JAVA_ERROR),
    "javascript": ("constructs.js", _JS, "syntax_error.js", _JS_ERROR),
    "php": ("constructs.php", _PHP, "syntax_error.php", _PHP_ERROR),
    "python": ("constructs.py", _PY, "syntax_error.py", _PY_ERROR),
    "rust": ("constructs.rs", _RUST, "syntax_error.rs", _RUST_ERROR),
    "typescript": ("constructs.ts", _TS, "syntax_error.ts", _TS_ERROR),
}


def _cases_for(language: str) -> tuple[GoldenCase, ...]:
    """The three standard inputs of one language."""
    constructs, source, error_name, error_source = _PLAIN[language]
    hostile_name, template = HOSTILE_TEMPLATES[language]
    return (
        GoldenCase(language, constructs, source.encode("utf-8"), clean=True),
        GoldenCase(language, error_name, error_source.encode("utf-8"), clean=False),
        GoldenCase(language, hostile_name, hostile_bytes(template), clean=True),
    )


CASES: tuple[GoldenCase, ...] = (
    *(case for language in V1_LANGUAGES for case in _cases_for(language)),
    GoldenCase("typescript", "component.tsx", _TSX.encode("utf-8"), clean=True),
)


# ── the digest (the one definition; the regen script imports it) ─────────────


def model_for(name: str, source: bytes, workdir: Path) -> FileModel:
    """Write ``source`` as ``workdir/name`` and build its model the production way.

    Every variant gets its own path: the read cache is keyed by path alone and
    a same-size rewrite can keep its mtime, so reusing a path could answer
    with the previous content.
    """
    model = get_model(write(workdir / name, source))
    assert model is not None, (
        f"get_model returned None for golden input {name}: every golden input must "
        "build a model (a syntax error is error_nodes > 0, not a fallback; LLD §5)"
    )
    return model


def _node_row(model: FileModel, i: int) -> list[object]:
    """One node's structure: kind, parent, field, span, line, text, admitted value."""
    kind = Kind(model.kind(i))
    start, end = model.span(i)
    value = model.literal(i).value if kind == Kind.LITERAL else None
    return [
        kind.name,
        model.parent(i),
        Field(model.field(i)).name,
        start,
        end,
        model.line(i),
        model.ident(i),
        value,
    ]


def structural_digest(model: FileModel) -> str:
    """sha256 of the model's canonical structure (sorted-key, ASCII JSON)."""
    canonical = {
        "language": model.language,
        "size": model.size,
        "error_nodes": model.error_nodes,
        "unmapped": dict(model.unmapped),
        "nodes": [_node_row(model, i) for i in range(model.node_count)],
    }
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("ascii")).hexdigest()


def digest_of(case: GoldenCase, workdir: Path) -> str:
    """The digest of one golden input as the installed layer parses it now."""
    return structural_digest(model_for(case.name, case.source, workdir / case.language))


def read_golden(path: Path) -> str:
    """The recorded digest; fails the test with the regeneration command when absent."""
    if not path.is_file():
        pytest.fail(
            f"missing golden {path}: generate it with {REGEN_COMMAND}, then review "
            "the diff (LLD D14)",
            pytrace=False,
        )
    data = path.read_bytes()
    if _DIGEST_FORMAT.fullmatch(data) is None:
        pytest.fail(
            f"malformed golden {path}: expected one line of 64 lowercase hex digits; "
            f"regenerate it with {REGEN_COMMAND}",
            pytrace=False,
        )
    return data[:64].decode("ascii")


# ── helpers ───────────────────────────────────────────────────────────────────


def _buffer(path: Path) -> bytes:
    """The bytes the parent ships: ``read_file_safe`` text, UTF-8 encoded (§4)."""
    text = read_file_safe(path)
    assert text is not None, f"read_file_safe could not read {path}"
    return text.encode("utf-8")


def _oracle_grammar(case: GoldenCase) -> tuple[str, str]:
    """The grammar the LLD names for a golden input (§6.3): the independent oracle that the
    input parses the way its case claims. ``.tsx`` is the one suffix whose grammar differs
    from its language's default."""
    return TSX_GRAMMAR if Path(case.name).suffix == ".tsx" else GRAMMARS[case.language]


def _oracle_tree(case: GoldenCase, buffer: bytes) -> tree_sitter.Tree:
    return tree_sitter.Parser(grammar(*_oracle_grammar(case))).parse(buffer)


def _has_error_node(node: tree_sitter.Node) -> bool:
    return node.type == "ERROR" or any(_has_error_node(child) for child in node.children)


def _node_problems(model: FileModel, i: int, newlines: list[int], size: int) -> list[str]:
    """§6.2 / D21: a span inside the buffer, an earlier parent, a ``\\n``-only line."""
    start, end = model.span(i)
    parent = model.parent(i)
    line = bisect.bisect_left(newlines, start) + 1
    checks = (
        (0 <= start <= end <= size, f"node {i}: span {start}..{end} outside 0..{size}"),
        (parent == -1 if i == 0 else 0 <= parent < i, f"node {i}: parent {parent}"),
        (model.line(i) == line, f"node {i}: line {model.line(i)}, newline-only {line}"),
    )
    return [message for ok, message in checks if not ok]


def _misfiled(model: FileModel) -> list[str]:
    """Nodes the per-kind index lists under a kind that is not their own."""
    return [
        f"node {i} listed under {kind.name}"
        for kind in Kind
        for i in model.nodes(kind)
        if Kind(model.kind(i)) != kind
    ]


def _index_problems(model: FileModel) -> list[str]:
    """The per-kind index lists every node once, under its own kind."""
    listed = sorted(i for kind in Kind for i in model.nodes(kind))
    partition = [] if listed == list(range(len(listed))) else ["per-kind index is not 0..n-1"]
    return partition + _misfiled(model)


def _model_problems(model: FileModel, buffer: bytes) -> list[str]:
    """Every node checked against the shipped buffer, plus the per-kind index."""
    newlines = [match.start() for match in re.finditer(b"\n", buffer)]
    nodes = range(model.node_count)
    problems = [p for i in nodes for p in _node_problems(model, i, newlines, len(buffer))]
    return problems + _index_problems(model)


def _golden_files() -> set[Path]:
    """Every file under ``_golden/`` (none before the first regeneration)."""
    if not GOLDEN_DIR.is_dir():
        return set()
    return {path for path in GOLDEN_DIR.rglob("*") if path.is_file()}


def _cases(language: str) -> list[GoldenCase]:
    return [case for case in CASES if case.language == language]


def _digest_map(cases: Iterable[GoldenCase], workdir: Path) -> dict[str, str]:
    return {case.name: digest_of(case, workdir) for case in cases}


# ── inventory: nine profiles, each with inputs and goldens, nothing stale ─────


def test_golden_inputs_cover_exactly_the_v1_profiles() -> None:
    """Goldens exist for the nine v1 languages, which are exactly ``PROFILES``."""
    assert {case.language for case in CASES} == set(V1_LANGUAGES) == set(PROFILES)


@pytest.mark.parametrize("language", sorted(PROFILES))
def test_every_profile_has_a_clean_and_an_error_input(language: str) -> None:
    """LLD §6.4: a profile ships golden inputs; each pins a clean and a partial parse."""
    outcomes = sorted({case.clean for case in _cases(language)})
    assert outcomes == [False, True], f"{language}: golden inputs {outcomes}"


def test_no_orphan_or_stray_golden_files() -> None:
    """Every file under ``_golden/`` is the digest of a current input."""
    stale = _golden_files() - {case.golden for case in CASES}
    assert sorted(stale) == [], f"stale goldens; rerun {REGEN_COMMAND}"


# ── the inputs are what they claim (independent oracle, this process) ─────────


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_golden_input_parses_as_declared(case: GoldenCase, tmp_path: Path) -> None:
    """The LLD-named grammar parses a clean input with no error and an error input
    with a real ERROR node, so the model's ``error_nodes`` is decidable either way."""
    tree = _oracle_tree(case, _buffer(write(tmp_path / case.name, case.source)))
    observed = (not tree.root_node.has_error, _has_error_node(tree.root_node))
    assert observed == (case.clean, not case.clean), case.case_id


# ── the model the layer builds for each input ─────────────────────────────────


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_model_language_and_ownership_match_the_parse(case: GoldenCase, tmp_path: Path) -> None:
    """The profile follows the extension; ``owns`` ⇔ ``error_nodes == 0`` (D10, §5)."""
    model = model_for(case.name, case.source, tmp_path)
    observed = (model.language, model.error_nodes == 0, owns(tmp_path / case.name) is not None)
    assert observed == (case.language, case.clean, case.clean), case.case_id


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_model_spans_and_lines_follow_the_shipped_buffer(
    case: GoldenCase, tmp_path: Path
) -> None:
    """Byte spans into the parent's re-encoded text; lines count ``\\n`` only (T5, D21)."""
    model = model_for(case.name, case.source, tmp_path)
    buffer = _buffer(tmp_path / case.name)
    observed = (model.size, Kind(model.kind(0)), _model_problems(model, buffer))
    assert observed == (len(buffer), Kind.MODULE, []), case.case_id


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.case_id)
def test_structural_digest_matches_golden(case: GoldenCase, tmp_path: Path) -> None:
    """The model's structure is the reviewed one (D14)."""
    expected = read_golden(case.golden)
    actual = digest_of(case, tmp_path)
    assert actual == expected, (
        f"{case.case_id}: structure changed ({expected} -> {actual}); if intended, "
        f"regenerate with {REGEN_COMMAND} and review the diff"
    )


@pytest.mark.parametrize("language", V1_LANGUAGES)
def test_digest_is_stable_across_fresh_workers(language: str, tmp_path: Path) -> None:
    """D14 determinism: a new worker process (new hash seed) builds the same model."""
    first = _digest_map(_cases(language), tmp_path / "first")
    reset_pool_for_tests()
    second = _digest_map(_cases(language), tmp_path / "second")
    assert first == second


# ── what the digest sees: structure, never comment or literal content ─────────

MUTATIONS: dict[str, tuple[Callable[[str], bytes], bool]] = {
    # (variant builder over a hostile template, digest expected unchanged?)
    "comment_same_length": (
        lambda t: hostile_bytes(t, comment=HOSTILE_COMMENT.replace("note", "nota")), True),
    "literal_same_length": (
        lambda t: hostile_bytes(t, literal="z" + HOSTILE_LITERAL[1:]), True),
    "identifier_renamed": (lambda t: hostile_bytes(t.replace("label", "lebal")), False),
    "comment_one_byte_longer": (
        lambda t: hostile_bytes(t, comment=HOSTILE_COMMENT.replace("note", "notes")), False),
}


@pytest.mark.parametrize("mutation", sorted(MUTATIONS))
@pytest.mark.parametrize("language", V1_LANGUAGES)
def test_digest_tracks_structure_not_content(language: str, mutation: str, tmp_path: Path) -> None:
    """A same-length comment or literal edit is invisible (D16: no literal text
    crosses the boundary; comments are not shipped); a renamed identifier or a
    one-byte shift is not."""
    name, template = HOSTILE_TEMPLATES[language]
    build, unchanged = MUTATIONS[mutation]
    base = structural_digest(model_for(name, hostile_bytes(template), tmp_path / "base"))
    variant = structural_digest(model_for(name, build(template), tmp_path / "variant"))
    assert (variant == base) == unchanged, f"{language} {mutation}"


# ── golden files: a missing or malformed one fails clearly ────────────────────


def test_missing_golden_names_the_regeneration_command(tmp_path: Path) -> None:
    with pytest.raises(pytest.fail.Exception, match=re.escape(REGEN_COMMAND)):
        read_golden(tmp_path / "javascript" / "constructs.js.sha256")


_HEX = "0123456789abcdef" * 4


@pytest.mark.parametrize(
    "content",
    [
        b"",
        _HEX.upper().encode(),
        _HEX[:63].encode(),
        (_HEX + "0").encode(),
        f"{_HEX}  constructs.js\n".encode(),
        f"{_HEX}\n\n".encode(),
        f"{_HEX}\r\n".encode(),
        f"\ufeff{_HEX}\n".encode(),
        f"{_HEX[:62]}g0\n".encode(),
    ],
    ids=["empty", "uppercase", "short", "long", "sha256sum_style", "two_lines", "crlf", "bom",
         "non_hex"],
)
def test_malformed_golden_fails_clearly(content: bytes, tmp_path: Path) -> None:
    path = tmp_path / "constructs.js.sha256"
    path.write_bytes(content)
    with pytest.raises(pytest.fail.Exception, match="malformed golden"):
        read_golden(path)


@pytest.mark.parametrize("content", [_HEX.encode(), f"{_HEX}\n".encode()], ids=["bare", "newline"])
def test_well_formed_golden_reads(content: bytes, tmp_path: Path) -> None:
    path = tmp_path / "constructs.js.sha256"
    path.write_bytes(content)
    assert read_golden(path) == _HEX
