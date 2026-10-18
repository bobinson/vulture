"""Seeded JavaScript + Python source tree for the AST bench (feature 0102, LLD §13.5).

``generate(root)`` writes ``FILES`` files of ``TREE_BYTES`` bytes in all under ``root``. Even
indexes are JavaScript and odd ones Python. Each file is a header followed by units (functions,
classes, and source-to-sink handlers for the path, request and command families) taken from
the template tables below. A unit that would overrun the file's share is not written; a
comment line pads the file to exactly its share. Every template parses without an ERROR node
in the v1 grammars, so the bench times the parse and model path, not the fallback path.

Density (A6). Every cost of the layer is per node, so the tree must have the node density of
real code, not of code with no prose: the templates alone measure 160k model nodes per 10^6
bytes, against the spike target's ~94k. Each unit is therefore preceded by a seeded comment
block (``PROSE_LINES``, ``PROSE_WORDS``), calibrated so that seed ``SEED`` measures ``DENSITY``
model nodes per 10^6 bytes (491,100 nodes over 5,242,880 bytes, sha256 ``28cce2af20145157...``,
with the grammar pack of 2026-10-17). The bench prints the measured density and refuses a run
that drifted from it.

Determinism: every draw comes from ``random.Random(seed).random()``. That is the only part of
``random`` Python promises to keep stable across versions (``choice`` and ``randrange`` may
change), so one seed writes the same bytes on every machine. ``Tree.digest`` (sha256 over
each relative path and its bytes, in write order) shows drift if it ever happens.

    python tests/perf/gen_tree.py OUT_DIR     # OUT_DIR must be absent or empty
"""

from __future__ import annotations

import hashlib
import random
import re
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

__all__ = ["DENSITY", "FILES", "SEED", "TREE_BYTES", "Tree", "generate"]

FILES = 1_000
TREE_BYTES = 5 * 1024 * 1024
SEED = 102
DIRS = 25  # FILES / DIRS files per directory
PROSE_LINES = 7  # A6: a unit's comment block is 1 .. PROSE_LINES lines
PROSE_WORDS = 5  # A6: of PROSE_WORDS .. 2 x PROSE_WORDS - 1 words each
DENSITY = 93_670  # A6: model nodes per 10^6 bytes this tree measures (the spike target: ~94k)

# Generic nouns, none a keyword or reserved word in JavaScript or Python, so each one is a
# legal property name and a two-word join is a legal identifier in both languages.
WORDS = (
    "account", "asset", "batch", "bucket", "cache", "channel", "chunk", "config", "cursor",
    "digest", "draft", "entry", "event", "folder", "frame", "graph", "handle", "header",
    "image", "item", "job", "layer", "ledger", "limit", "member", "message", "metric",
    "note", "offset", "order", "owner", "page", "panel", "photo", "profile", "queue",
    "record", "report", "result", "route", "sample", "schema", "session", "shard", "status",
    "table", "target", "task", "tenant", "ticket", "token", "upload", "user", "volume",
    "widget",
)  # fmt: skip

# A unit's placeholders: ``<<id3>>``. The letters name the kind of value (``_KINDS``); one
# name has one value within a unit.
_SLOT = re.compile(r"<<([A-Za-z]+)(\d*)>>")

_JS_HEADER = """\
"use strict";
const fs = require("fs");
const path = require("path");
const childProcess = require("child_process");
const BASE_DIR = "/srv/data";
"""

_JS_UNITS = (
    """
function <<id1>>(<<id2>>, <<id3>>) {
  const <<id4>> = <<id2>>.<<p1>>.<<p2>>;
  let <<id5>> = "<<t1>>-" + <<id4>>;
  if (<<id5>>.length > <<n1>>) {
    <<id5>> = <<id6>>(<<id5>>, <<id3>>);
  } else {
    <<id5>> = `${<<id4>>}/<<t2>>`;
  }
  for (const <<id7>> of <<id3>>.<<p3>>) {
    <<id5>> += <<id7>>.<<p1>>;
  }
  return <<id5>>;
}
""",
    """
function <<id1>>(req, res) {
  const <<id2>> = req.query.<<p1>>;
  const <<id3>> = path.join(BASE_DIR, <<id2>>);
  if (!<<id3>>.startsWith(BASE_DIR)) {
    return res.status(400).end();
  }
  fs.readFile(<<id3>>, (err, data) => res.send(data));
}
""",
    """
function <<id1>>(req, res) {
  const <<id2>> = req.body.<<p1>>;
  childProcess.exec("ls " + <<id2>>, (err, out) => res.send(out));
}
""",
    """
async function <<id1>>(req) {
  const <<id2>> = req.query.<<p1>>;
  const <<id3>> = await fetch(<<id2>>, { method: "GET" });
  return <<id3>>.json();
}
""",
    """
class <<C1>> {
  constructor(<<id1>>) {
    this.<<p1>> = <<id1>>;
    this.<<p2>> = [];
  }

  <<id2>>(<<id3>>) {
    try {
      return this.<<p1>>[<<id3>>] || <<n1>>;
    } catch (err) {
      this.<<p2>>.push(err.message);
      return null;
    }
  }
}
""",
    """
const <<id1>> = ({ <<p1>>, <<p2>> }, <<id2>>) => {
  let <<id3>> = 0;
  while (<<id3>> < <<n1>>) {
    <<id2>>[<<id3>>] = <<p1>> ? <<p2>> : "<<t1>>";
    <<id3>> += 1;
  }
  return { <<p1>>, total: <<id3>> };
};
""",
)

_PY_HEADER = """\
import os
import subprocess
from urllib.request import urlopen

BASE_DIR = "/srv/data"
"""

_PY_UNITS = (
    '''

def <<id1>>(<<id2>>, <<id3>>=<<n1>>):
    <<id4>> = <<id2>>.get("<<t1>>", "<<t2>>")
    <<id5>> = "<<t1>>-" + str(<<id4>>)
    if len(<<id5>>) > <<id3>>:
        <<id5>> = <<id6>>(<<id5>>, <<id3>>)
    elif <<id4>>:
        <<id5>> = f"{<<id4>>}/<<t2>>"
    else:
        <<id5>> = <<id5>>.strip()
    for <<id7>> in <<id2>>.<<p1>>:
        <<id5>> += <<id7>>.<<p2>>
    return <<id5>>
''',
    '''

def <<id1>>(request):
    <<id2>> = request.args["<<p1>>"]
    <<id3>> = os.path.join(BASE_DIR, <<id2>>)
    if not <<id3>>.startswith(BASE_DIR):
        return None
    with open(<<id3>>) as handle:
        return handle.read()
''',
    '''

def <<id1>>(request):
    <<id2>> = request.args.get("<<p1>>")
    return subprocess.check_output("ls " + <<id2>>, shell=True)
''',
    '''

def <<id1>>(request):
    <<id2>> = request.args.get("<<p1>>")
    with urlopen(<<id2>>) as <<id3>>:
        return <<id3>>.read()
''',
    '''

class <<C1>>:
    def __init__(self, <<id1>>):
        self.<<p1>> = <<id1>>
        self.<<p2>> = []

    def <<id2>>(self, <<id3>>):
        try:
            return self.<<p1>>[<<id3>>]
        except (KeyError, IndexError) as exc:
            self.<<p2>>.append(str(exc))
            return <<n1>>
''',
    '''

def <<id1>>(<<id2>>):
    <<id3>> = [<<id4>>.<<p1>> for <<id4>> in <<id2>> if <<id4>>.<<p2>>]
    <<id5>> = 0
    while <<id5>> < len(<<id3>>):
        <<id3>>[<<id5>>] = <<id3>>[<<id5>>] or "<<t1>>"
        <<id5>> += 1
    return {"<<t1>>": <<id3>>, "total": <<id5>>}
''',
)


@dataclass(frozen=True, slots=True)
class _Lang:
    """One language of the tree: its suffix, header, unit templates and spelling rules."""

    suffix: str
    header: str
    units: tuple[str, ...]
    comment: str
    join: Callable[[str, str], str]


def _camel(first: str, second: str) -> str:
    return first + second.capitalize()


def _snake(first: str, second: str) -> str:
    return f"{first}_{second}"


_LANGS = (
    _Lang(".js", _JS_HEADER, _JS_UNITS, "// ", _camel),
    _Lang(".py", _PY_HEADER, _PY_UNITS, "# ", _snake),
)


class _Rng:
    """Draws built on ``random()`` alone, the stream Python keeps stable across versions."""

    def __init__(self, seed: int) -> None:
        self._random = random.Random(seed).random

    def unit(self) -> float:
        return self._random()

    def below(self, n: int) -> int:
        return int(self._random() * n)

    def pick(self, items: Sequence[str]) -> str:
        return items[self.below(len(items))]


def _identifier(lang: _Lang, rng: _Rng) -> str:
    return lang.join(rng.pick(WORDS), rng.pick(WORDS))


def _class_name(_lang: _Lang, rng: _Rng) -> str:
    return rng.pick(WORDS).capitalize() + rng.pick(WORDS).capitalize()


def _word(_lang: _Lang, rng: _Rng) -> str:
    return rng.pick(WORDS)


def _number(_lang: _Lang, rng: _Rng) -> str:
    return str(1 + rng.below(999))


# Placeholder letters -> how its value is drawn (one dict lookup per placeholder).
_KINDS: dict[str, Callable[[_Lang, _Rng], str]] = {
    "id": _identifier,
    "C": _class_name,
    "p": _word,
    "t": _word,
    "n": _number,
}


@dataclass(frozen=True, slots=True)
class Tree:
    """A generated tree: its root, its files in write order, their total size and digest."""

    root: Path
    paths: tuple[Path, ...]
    total_bytes: int
    digest: str


def generate(root: Path, *, seed: int = SEED, files: int = FILES, total: int = TREE_BYTES) -> Tree:
    """Write the seeded tree under ``root`` and describe it."""
    rng = _Rng(seed)
    digest = hashlib.sha256()
    paths: list[Path] = []
    written = 0
    for index, size in enumerate(_sizes(rng, files, total)):
        relative, data = _emit(root, index, size, rng)
        digest.update(relative.as_posix().encode("ascii") + b"\0" + data)
        paths.append(root / relative)
        written += len(data)
    return Tree(root, tuple(paths), written, digest.hexdigest())


def _sizes(rng: _Rng, files: int, total: int) -> list[int]:
    """Each file's share of ``total``: jittered to 0.5-1.5x the mean, summing to ``total``."""
    weights = [0.5 + rng.unit() for _ in range(files)]
    scale = total / sum(weights)
    sizes = [int(weight * scale) for weight in weights]
    sizes[-1] += total - sum(sizes)
    return sizes


def _emit(root: Path, index: int, size: int, rng: _Rng) -> tuple[Path, bytes]:
    """Write file ``index`` (``size`` bytes); return its path under ``root`` and its bytes."""
    lang = _LANGS[index % len(_LANGS)]
    relative = Path(f"pkg{index % DIRS:02d}", f"mod{index:04d}{lang.suffix}")
    data = _source(lang, size, rng).encode("ascii")
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return relative, data


def _source(lang: _Lang, size: int, rng: _Rng) -> str:
    """The header, then whole units while they fit in ``size``, then the padding."""
    parts = [lang.header]
    used = len(lang.header)
    unit = _unit(lang, rng)
    while used + len(unit) <= size:
        parts.append(unit)
        used += len(unit)
        unit = _unit(lang, rng)
    parts.append(_padding(lang, size - used))
    return "".join(parts)


def _unit(lang: _Lang, rng: _Rng) -> str:
    """A prose comment block, then one template with each placeholder filled; a name repeats
    its value in the unit."""
    values: dict[str, str] = {}

    def fill(match: re.Match[str]) -> str:
        name = match.group(0)
        if name not in values:
            values[name] = _KINDS[match.group(1)](lang, rng)
        return values[name]

    return _prose(lang, rng) + _SLOT.sub(fill, rng.pick(lang.units))


def _prose(lang: _Lang, rng: _Rng) -> str:
    """A6: the comment block in front of a unit, ``1 .. PROSE_LINES`` lines of
    ``PROSE_WORDS`` words or more."""
    lines = 1 + rng.below(PROSE_LINES)
    return "".join(_prose_line(lang, rng) for _ in range(lines))


def _prose_line(lang: _Lang, rng: _Rng) -> str:
    words = PROSE_WORDS + rng.below(PROSE_WORDS)
    return "\n" + lang.comment + " ".join(rng.pick(WORDS) for _ in range(words))


def _padding(lang: _Lang, n: int) -> str:
    """Exactly ``n`` bytes: a blank line, a comment line, or bare newlines when no comment
    fits (``"\\n" + comment + filler + "\\n"`` needs ``len(comment) + 2`` bytes)."""
    filler = n - len(lang.comment) - 2
    if filler < 0:
        return "\n" * max(n, 0)
    return "\n" + lang.comment + "x" * filler + "\n"


def main(argv: list[str]) -> int:
    """CLI: write the tree under ``argv[0]``, which must be absent or empty."""
    if len(argv) != 1:
        raise SystemExit("usage: gen_tree.py OUT_DIR")
    root = Path(argv[0])
    if root.exists() and any(root.iterdir()):
        raise SystemExit(f"{root} is not empty; refusing to write into it")
    tree = generate(root)
    print(f"{len(tree.paths)} files, {tree.total_bytes} bytes, sha256 {tree.digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
