"""Feature 0104 -- the recall it gives up, pinned at the answer the rules give (HT-13 (c)).

Two kinds of pin, each a staged tree scanned by the two AST skills on a neutral root:

* ACCEPTED LOSSES (D-N (1), (4), (6); user-decided): the post-rule answer, so each is RED
  until its workstream lands and then holds the loss exactly where it was accepted -- a rule
  that silences more, or a change that silently restores the row, fails here.
  - C: the cross-file existence oracle, including the JS serve-file helpers (a probe helper in
    one file, the request and the served file in another); K5 t7 (an exported opener's
    ``lstatSync`` probe, while its open and the caller's read stay); C-R1, a ``"use server"``
    export probing its bare positional parameter.
  - D: a ``hash`` the file does not bind is trusted as a digest (an imported helper named
    ``hash``; a bcrypt-style output); and rev 3's residual (A55): a ``hash`` bound through
    ``functools.partial``, and a Java lambda implementing an imported ``Hasher``.
  - H: H2L, a ``readall`` keyed read with no file-system evidence (Go and JS; a receiver
    whose words show a file system keeps its row); H3L, a Go
    same-package path helper in a sibling file, and its dot-import extension (``. "os"``).
* OUT-OF-SCOPE GAPS: today's answer, green now and after 0104 (no 0104 rule is meant to move
  them): a Go serve-file sink, and a C++ parameter whose default value hides the hint.

A site is ``(file, line, category, verdict)``; ``finding`` is a row of that category on that
line, ``clean`` is none.
"""

from __future__ import annotations

from pathlib import Path
from typing import NamedTuple

import pytest

from tests import _ast_v1
from tests._0104_sites import CHECK
from tests._neutral import neutral_dir
from tests.e2e._0101_markers import Site, verdicts


class Gap(NamedTuple):
    files: dict[str, str]
    sites: tuple[tuple[str, int, str, str], ...]  # (file, line, category, verdict)


_JS_PROBE_HELPER = """const fs = require("node:fs");

function present(filePath) {
  return fs.existsSync(filePath);
}

module.exports = { present };
"""

LOSSES = {
    "c_cross_file_oracle": Gap({
        "store.js": _JS_PROBE_HELPER,
        "routes.js": """const { present } = require("./store");

function register(app) {
  app.get("/exists", (req, res) => res.json({ ok: present(String(req.query.name)) }));
}

module.exports = { register };
""",
    }, (("store.js", 4, "CWE-22", "clean"),)),
    "c_js_serve": Gap({
        "store.js": _JS_PROBE_HELPER,
        "routes.js": """const path = require("node:path");
const { present } = require("./store");

const SHELF_ROOT = "/srv/shelf";

function register(app) {
  app.get("/shelf", (req, res) => {
    const target = path.join(SHELF_ROOT, String(req.query.name));
    if (!present(target)) {
      return res.sendStatus(404);
    }
    return res.sendFile(target);
  });
}

module.exports = { register };
""",
    }, (("store.js", 4, "CWE-22", "clean"), ("routes.js", 12, "CWE-22", "finding"))),
    "c_js_koa_serve": Gap({
        "store.js": _JS_PROBE_HELPER,
        "routes.js": """const send = require("koa-send");
const { present } = require("./store");

const SHELF_ROOT = "/srv/shelf";

async function fetchShelf(ctx) {
  const target = SHELF_ROOT + "/" + ctx.query.name;
  if (!present(target)) {
    ctx.throw(404);
  }
  await send(ctx, target, { root: "/" });
}

module.exports = { fetchShelf };
""",
    }, (("store.js", 4, "CWE-22", "clean"), ("routes.js", 11, "CWE-22", "clean"))),
    "c_k5_t7_opener": Gap({
        "lib/opener.js": """const fs = require("fs");

// Refuse anything but a regular file, then open it without following a link.
function openChecked(filePath) {
  if (!fs.lstatSync(filePath).isFile()) {
    return null;
  }
  const fd = fs.openSync(filePath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  return { path: filePath, fd };
}

module.exports = { openChecked };
""",
        "notes.js": """const fs = require("fs");
const path = require("path");
const http = require("http");
const { openChecked } = require("./lib/opener");

const NOTES = "/srv/notes";

http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const name = url.searchParams.get("file");
    const opened = openChecked(path.join(NOTES, name));
    if (!opened) {
      res.statusCode = 404;
      res.end();
      return;
    }
    try {
      res.end(fs.readFileSync(opened.fd));
    } finally {
      fs.closeSync(opened.fd);
    }
  })
  .listen(8080);
""",
    }, (("lib/opener.js", 5, "CWE-22", "clean"), ("lib/opener.js", 8, "CWE-22", "finding"),
        ("notes.js", 19, "CWE-22", "finding"))),
    "c_r1_use_server": Gap({
        "app/sheets/actions.ts": """"use server";

import fs from "node:fs";

export async function sheetExists(filePath: string): Promise<boolean> {
  return fs.existsSync(filePath);
}
""",
        "app/sheets/info.ts": """"use server";

import { stat } from "node:fs/promises";

export async function sheetInfo(filePath: string) {
  const info = await stat(filePath);
  return { size: info.size, folder: info.isDirectory() };
}
""",
    }, (("app/sheets/actions.ts", 6, "CWE-22", "clean"),
        ("app/sheets/info.ts", 6, "CWE-22", "clean"))),
    "d_imported_hash": Gap({
        "page.js": """const fs = require('fs')
const routes = require('./routes')
exports.page = function (req, res) {
  res.send(fs.readFileSync(routes.hash(req.query.p)))
}
""",
    }, (("page.js", 4, "CWE-22", "clean"),)),
    "d_bcrypt_style": Gap({
        "vault.js": """const fs = require('fs')
const path = require('path')
const bcrypt = require('bcrypt')
exports.store = async function (req, res) {
  const sealed = await bcrypt.hash(req.body.secret, 10)
  fs.appendFileSync(path.join('/srv/vault', sealed), 'x')
  res.end()
}
""",
    }, (("vault.js", 6, "CWE-22", "clean"),)),
    "d_partial_hash": Gap({
        "shelf.py": """import functools
import os

from flask import request

hash = functools.partial(os.path.join, "/srv/shelf")


def shelf():
    with open(hash(request.args["name"])) as fh:
        return fh.read()
""",
    }, (("shelf.py", 10, "CWE-22", "clean"),)),
    "d_java_lambda_hasher": Gap({
        "src/Shelf.java": """import java.nio.file.Files;
import java.nio.file.Paths;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.example.shelf.Hasher;

public class Shelf extends HttpServlet {
    private final Hasher layout = name -> name.substring(0, 2) + "/" + name;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws java.io.IOException {
        String n = req.getParameter("n");
        byte[] body = Files.readAllBytes(Paths.get("/srv/shelf", layout.hash(n)));
        resp.getOutputStream().write(body);
    }
}
""",
    }, (("src/Shelf.java", 15, "CWE-22", "clean"),)),
    "h2l_go_readall": Gap({
        "svc/store.go": """package svc

import (
	"net/http"

	"example.invalid/blobshelf"
)

var shelf = blobshelf.Open("/srv/shelf")
var files = blobshelf.Open("/srv/files")

func Fetch(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("p")
	shelf.ReadAll(name)
	files.ReadAll(name)
}
""",
    }, (("svc/store.go", 14, "CWE-22", "clean"), ("svc/store.go", 15, "CWE-22", "finding"))),
    "h2l_js_readall": Gap({
        "app/store.js": """const fs = require("fs");

function readAll(p) {
  return fs.readFileSync(p);
}

module.exports = { readAll };
""",
        "app/blob.js": """const express = require("express");
const { readAll } = require("./store");

const app = express();

app.get("/b", (req, res) => {
  res.send(readAll(req.query.p));
});
""",
    }, (("app/blob.js", 7, "CWE-22", "clean"),)),
    "h3l_sibling_helper": Gap({
        "svc/handler.go": """package svc

import "net/http"

func Files(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("p")
	open(name)
	remove(name)
	readFile(name)
}
""",
        "svc/fsutil.go": """package svc

import "os"

func open(p string) (*os.File, error) { return os.Open(p) }

func remove(p string) error { return os.Remove(p) }

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
""",
    }, (("svc/handler.go", 7, "CWE-22", "clean"), ("svc/handler.go", 8, "CWE-22", "clean"),
        ("svc/handler.go", 9, "CWE-22", "finding"))),
    "h3l_dot_import_os": Gap({
        "svc/dot.go": """package svc

import (
	"net/http"
	. "os"
)

func Files(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("p")
	Open(name)
	Remove(name)
	ReadFile(name)
}
""",
    }, (("svc/dot.go", 10, "CWE-22", "clean"), ("svc/dot.go", 11, "CWE-22", "clean"),
        ("svc/dot.go", 12, "CWE-22", "finding"))),
}

OUT_OF_SCOPE = {
    "q11_go_servefile": Gap({
        "handler.go": """package files

import (
	"net/http"
	"path/filepath"
)

const root = "/srv/files"

func Download(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	http.ServeFile(w, r, filepath.Join(root, name))
}
""",
    }, (("handler.go", 12, "CWE-22", "clean"),)),
    "s6_cpp_default_arg": Gap({
        "src/pages.cpp": """#include <fstream>
#include <sstream>
#include <string>

static const std::string kPageDir = "/srv/app/pages/";

std::string loadPage(const std::string& fileName = "index.html") {
    std::ifstream in(kPageDir + fileName);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}
""",
        "src/pages_plain.cpp": """#include <fstream>
#include <sstream>
#include <string>

static const std::string kPageDir = "/srv/app/pages/";

std::string loadPagePlain(const std::string& fileName) {
    std::ifstream in(kPageDir + fileName);
    std::stringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}
""",
    }, (("src/pages.cpp", 8, "CWE-22", "clean"), ("src/pages_plain.cpp", 8, "CWE-22", "finding"))),
}


def _staged(request: pytest.FixtureRequest, gap: Gap) -> Path:
    root = neutral_dir(request) / "app"
    for rel, text in gap.files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


Observed = tuple[str, int, str, str]


def _verdict(rows: list[_ast_v1.Finding], root: Path, site: Observed) -> Observed:
    """``site`` with the verdict ``rows`` give it (``_0101_markers.verdicts``)."""
    rel, line, category, want = site
    marker = Site(rel, line, want, CHECK[category])
    return rel, line, category, verdicts(rows, [marker], category, root)[marker]


def _observed(request: pytest.FixtureRequest, gap: Gap) -> list[Observed]:
    """Each site of ``gap`` with the verdict the two skills give on its staged tree. Every
    staged file must be one the AST tier owns, so a ``clean`` site never passes on a file the
    tier stopped reading."""
    root = _staged(request, gap)
    staged = {str(root / rel) for rel in gap.files}
    assert _ast_v1.ast_owned(staged) == staged, "a staged file is not AST-owned"
    rows = _ast_v1.migrated_rows(root)
    return [_verdict(rows, root, site) for site in gap.sites]


@pytest.mark.parametrize("name", sorted(LOSSES))
def test_accepted_loss_holds_where_it_was_accepted(
    request: pytest.FixtureRequest, name: str,
) -> None:
    gap = LOSSES[name]
    assert _observed(request, gap) == list(gap.sites)


@pytest.mark.parametrize("name", sorted(OUT_OF_SCOPE))
def test_out_of_scope_gap_keeps_todays_answer(
    request: pytest.FixtureRequest, name: str,
) -> None:
    gap = OUT_OF_SCOPE[name]
    assert _observed(request, gap) == list(gap.sites)
