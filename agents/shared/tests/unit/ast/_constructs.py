"""Feature 0102 plan task 2.1: the ``CONSTRUCTS`` table of the scope tests. Not a test module.

Each row is ``(name, {lang: source}, sink_ident, expected_def_line)`` over the nine v1 language
codes (``_analysis.LANGS``): a small program whose read of ``sink_ident`` inside ``sink(...)``
must resolve (LLD §7) to the Def that starts on ``expected_def_line`` — and to no other. The
line is the same in every language: line 1 is a per-language header (``package main``,
``<?php``, Java's ``class A {``, else a comment) and every body starts on line 2.

A construct a language lacks is ``None`` in ``sources``, and the row's ``lacks`` names why;
the tests skip that cell with the reason (``construct_source``).

The rows: the plain bindings (assign, overwrite, param, loop target, catch, closure, class
method, module read), the revision-9 decisions (L10's ``arm``) and the walk corrections W6,
W7, W11 and W13 (``pair_leaf``, ``rest_leaf``, ``pattern_param``, ``typed_param``,
``decorated_param``, ``multi_target``, ``import_pair``, ``global_write``). The ``arm`` row
also reads ``name`` after the match (``after(name)``) and rewrites it on
``ARM_SANITIZED_LINE`` inside the first arm, so the L10 join test reuses its sources; every
profile ships an arm as a BLOCK child of an OTHER node, which the pass reads as one
alternative (A25). The shapes A25 leaves unsupported in v1 — Rust ``static``/``const``, Rust,
Go and PHP aliased imports, C++ ``[[attr]]`` — stay ``None`` cells.

Imports no Phase-2 module: the scope pass is reached by the tests, never here.
"""

from __future__ import annotations

import functools
from collections.abc import Mapping
from textwrap import dedent
from types import MappingProxyType
from typing import NamedTuple

import pytest

from shared.ast import FileModel
from shared.ast.kinds import Kind
from tests.unit.ast._analysis import LANGS, call_at, language_of, model_of


class Construct(NamedTuple):
    """One scope construct in every language that has it (plan task 2.1)."""

    name: str
    sources: Mapping[str, str | None]  # lang code -> program; None: the language lacks it
    sink_ident: str  # the identifier read inside sink(...)
    expected_def_line: int  # the one line the reaching Def(s) start on
    lacks: Mapping[str, str]  # lang code -> why that language lacks the construct


# Line 1 of every program: what the language needs before a body (Java's class closes after).
_HEADER: Mapping[str, str] = MappingProxyType({
    "js": "// construct", "ts": "// construct", "py": "# construct", "go": "package main",
    "java": "class A {", "rs": "// construct", "php": "<?php", "c": "// construct",
    "cpp": "// construct",
})
_FOOTER: Mapping[str, str] = MappingProxyType({"java": "}\n"})
# A dialect reuses its base language's body unless the row gives it its own.
_SAME_AS: Mapping[str, str] = MappingProxyType({"ts": "js", "cpp": "c"})

# The line of the first arm's rewrite in every ``arm`` source (the L10 Δ1).
ARM_SANITIZED_LINE = 6

# Why a language lacks a construct, shared by the rows that cite the same fact.
_NO_TRY = "has no try/catch: an error is an ordinary value (§6.3 maps no TRY/CATCH)"
_NO_NESTED = "has no nested function or lambda"
_NO_CLASS = "has no class (§6.3 C maps no CLASS)"
_NO_GLOBAL = "has no `global` statement: only the Python and PHP profiles ship GLOBAL (§6.3)"
_NO_DESTRUCT = "has no destructuring assignment"
_NO_KEYED = "has no keyed destructuring: its patterns are positional"
_NO_REST = "has no rest element in a destructuring pattern"
_NO_PATTERN_PARAM = "has no destructuring parameter"
_NO_DECORATOR = "has no decorator the v1 profile ships as DECORATOR (A25: C++ [[attr]] is a v1 gap)"
_NO_MULTI = "has no multi-target assignment"
_NO_ALIAS_PAIR = (
    "ships no import PAIR (§6.3: only JS/TS import_specifier and Python aliased_import; A25: "
    "Rust/Go/PHP aliased imports are a v1 gap)"
)


def _program(lang: str, body: str) -> str:
    """``body`` as a whole ``lang`` file: the header on line 1, the body from line 2."""
    return f"{_HEADER[lang]}\n{dedent(body)}{_FOOTER.get(lang, '')}"


def _body(bodies: Mapping[str, str], lang: str) -> str:
    return bodies.get(lang) or bodies[_SAME_AS[lang]]


def _row(
    name: str, ident: str, line: int, lacks: Mapping[str, str], bodies: Mapping[str, str]
) -> Construct:
    """A row: every language in ``lacks`` is ``None``, with its reason; every other one is
    ``bodies[lang]`` (a TS or C++ cell falls back to the JS or C body)."""
    sources = {
        lang: None if lang in lacks else _program(lang, _body(bodies, lang)) for lang in LANGS
    }
    return Construct(
        name, MappingProxyType(sources), ident, line, MappingProxyType(dict(lacks))
    )


CONSTRUCTS: tuple[Construct, ...] = (
    _row("assign", "x", 3, {}, {
        "js": """\
            function f(a) {
              const x = a;
              sink(x);
            }
            """,
        "py": """\
            def f(a):
                x = a
                sink(x)
            """,
        "go": """\
            func f(a string) {
                x := a
                sink(x)
            }
            """,
        "java": """\
            void f(String a) {
              String x = a;
              sink(x);
            }
            """,
        "rs": """\
            fn f(a: &str) {
                let x = a;
                sink(x);
            }
            """,
        "php": """\
            function f($a) {
                $x = $a;
                sink($x);
            }
            """,
        "c": """\
            void f(char *a) {
                char *x = a;
                sink(x);
            }
            """,
    }),
    # D6: an unconditional write overwrites — the first Def no longer reaches.
    _row("overwrite", "x", 4, {}, {
        "js": """\
            function f(a, b) {
              let x = a;
              x = b;
              sink(x);
            }
            """,
        "py": """\
            def f(a, b):
                x = a
                x = b
                sink(x)
            """,
        "go": """\
            func f(a string, b string) {
                x := a
                x = b
                sink(x)
            }
            """,
        "java": """\
            void f(String a, String b) {
              String x = a;
              x = b;
              sink(x);
            }
            """,
        "rs": """\
            fn f(a: &str, b: &str) {
                let mut x = a;
                x = b;
                sink(x);
            }
            """,
        "php": """\
            function f($a, $b) {
                $x = $a;
                $x = $b;
                sink($x);
            }
            """,
        "c": """\
            void f(char *a, char *b) {
                char *x = a;
                x = b;
                sink(x);
            }
            """,
    }),
    # C4: the C parameter is a pointer_declarator, unwrapped to its identifier.
    _row("param", "p", 2, {}, {
        "js": """\
            function f(p) {
              sink(p);
            }
            """,
        "py": """\
            def f(p):
                sink(p)
            """,
        "go": """\
            func f(p string) {
                sink(p)
            }
            """,
        "java": """\
            void f(String p) {
              sink(p);
            }
            """,
        "rs": """\
            fn f(p: &str) {
                sink(p);
            }
            """,
        "php": """\
            function f($p) {
                sink($p);
            }
            """,
        "c": """\
            void f(char *p) {
                sink(p);
            }
            """,
    }),
    _row("loop_target", "x", 3, {"c": "has no for-each loop: a `for` header binds no target"}, {
        "js": """\
            function f(xs) {
              for (const x of xs) {
                sink(x);
              }
            }
            """,
        "py": """\
            def f(xs):
                for x in xs:
                    sink(x)
            """,
        "go": """\
            func f(xs []string) {
                for _, x := range xs {
                    sink(x)
                }
            }
            """,
        "java": """\
            void f(String[] xs) {
              for (String x : xs) {
                sink(x);
              }
            }
            """,
        "rs": """\
            fn f(xs: Vec<String>) {
                for x in xs {
                    sink(x);
                }
            }
            """,
        "php": """\
            function f($xs) {
                foreach ($xs as $x) {
                    sink($x);
                }
            }
            """,
        "cpp": """\
            void f(std::vector<std::string> xs) {
                for (auto x : xs) {
                    sink(x);
                }
            }
            """,
    }),
    _row("catch", "e", 4, {"go": _NO_TRY, "rs": _NO_TRY, "c": _NO_TRY}, {
        "js": """\
            function f() {
              try { g(); }
              catch (e) {
                sink(e);
              }
            }
            """,
        "py": """\
            def f():
                try: g()
                except Exception as e:
                    sink(e)
            """,
        "java": """\
            void f() {
              try { g(); }
              catch (Exception e) {
                sink(e);
              }
            }
            """,
        "php": """\
            function f() {
                try { g(); }
                catch (Exception $e) {
                    sink($e);
                }
            }
            """,
        "cpp": """\
            void f() {
                try { g(); }
                catch (const std::exception &e) {
                    sink(e);
                }
            }
            """,
    }),
    # R-O (W13): a free name in a nested function reads the enclosing function's Def.
    _row("closure", "x", 3, {"c": _NO_NESTED}, {
        "js": """\
            function f(a) {
              const x = a;
              const g = () => sink(x);
              return g;
            }
            """,
        "py": """\
            def f(a):
                x = a
                g = lambda: sink(x)
                return g
            """,
        "go": """\
            func f(a string) func() {
                x := a
                g := func() { sink(x) }
                return g
            }
            """,
        "java": """\
            Runnable f(String a) {
              String x = a;
              Runnable g = () -> sink(x);
              return g;
            }
            """,
        "rs": """\
            fn f(a: &str) {
                let x = a;
                let g = || sink(x);
                g();
            }
            """,
        "php": """\
            function f($a) {
                $x = $a;
                $g = fn() => sink($x);
                return $g;
            }
            """,
        "cpp": """\
            void f(char *a) {
                char *x = a;
                auto g = [&]() { sink(x); };
                g();
            }
            """,
    }),
    # A3: a Go method's receiver list is a PARAMS ARGS too; Java nests a class in A.
    _row("class_method", "p", 3, {"c": _NO_CLASS}, {
        "js": """\
            class A {
              m(p) {
                sink(p);
              }
            }
            """,
        "py": """\
            class A:
                def m(self, p):
                    sink(p)
            """,
        "go": """\
            type A struct{}
            func (a *A) m(p string) {
                sink(p)
            }
            """,
        "java": """\
            static class B {
              void m(String p) {
                sink(p);
              }
            }
            """,
        "rs": """\
            impl A {
                fn m(&self, p: &str) {
                    sink(p);
                }
            }
            """,
        "php": """\
            class A {
                function m($p) {
                    sink($p);
                }
            }
            """,
        "cpp": """\
            class A {
                void m(char *p) {
                    sink(p);
                }
            };
            """,
    }),
    # R-O (W13): a top-level function reads a module Def.
    _row("module_read", "root", 2, {
        "java": "has no module-level binding: module_is_scope is False, every Def sits in a "
                "class (§6.3 Java)",
        "rs": "binds a module-level value only by a `static`/`const` item, which the v1 "
              "profile ships as no ASSIGN (§6.3 Rust; A25: a v1 gap)",
        "php": "lets a function read a module variable only through `global` (the "
               "global_write row)",
    }, {
        "js": """\
            const root = "docs";
            function f() {
              sink(root);
            }
            """,
        "py": """\
            root = "docs"
            def f():
                sink(root)
            """,
        "go": """\
            var root = "docs"
            func f() {
                sink(root)
            }
            """,
        "c": """\
            const char *root = "docs";
            void f() {
                sink(root);
            }
            """,
    }),
    # W13 (cwe_22_15): a write under `global` is a Def of the module, read by another function.
    _row("global_write", "path", 4, {
        "js": _NO_GLOBAL, "ts": _NO_GLOBAL, "go": _NO_GLOBAL, "java": _NO_GLOBAL,
        "rs": _NO_GLOBAL, "c": _NO_GLOBAL, "cpp": _NO_GLOBAL,
    }, {
        "py": """\
            def set_doc(request):
                global path
                path = request
            def read_doc():
                sink(path)
            """,
        "php": """\
            function set_doc($request) {
                global $path;
                $path = $request;
            }
            function read_doc() {
                global $path;
                sink($path);
            }
            """,
    }),
    # L10: each arm runs from the pre-match state, so the sink arm sees the Def on line 3 and
    # never the first arm's rewrite on ARM_SANITIZED_LINE; after the match both reach.
    _row("arm", "name", 3, {}, {
        "js": """\
            function f(a, mode) {
              let name = a;
              switch (mode) {
                case "leaf":
                  name = clean(name);
                  break;
                default:
                  sink(name);
              }
              after(name);
            }
            """,
        "py": """\
            def f(a, mode):
                name = a
                match mode:
                    case "leaf":
                        name = clean(name)
                    case _:
                        sink(name)
                after(name)
            """,
        "go": """\
            func f(a string, mode string) {
                name := a
                switch mode {
                case "leaf":
                    name = clean(name)
                default:
                    sink(name)
                }
                after(name)
            }
            """,
        "java": """\
            void f(String a, String mode) {
              String name = a;
              switch (mode) {
                case "leaf":
                  name = clean(name);
                  break;
                default:
                  sink(name);
              }
              after(name);
            }
            """,
        "rs": """\
            fn f(a: String, mode: &str) {
                let mut name = a;
                match mode {
                    "leaf" => {
                        name = clean(&name);
                    }
                    _ => sink(&name),
                }
                after(&name);
            }
            """,
        "php": """\
            function f($a, $mode) {
                $name = $a;
                switch ($mode) {
                    case "leaf":
                        $name = clean($name);
                        break;
                    default:
                        sink($name);
                }
                after($name);
            }
            """,
        "c": """\
            void f(char *a, int mode) {
                char *name = a;
                switch (mode) {
                case 1:
                    name = clean(name);
                    break;
                default:
                    sink(name);
                }
                after(name);
            }
            """,
    }),
    # W6: a PAIR leaf `{k: v} = x` binds v (<- x.k).
    _row("pair_leaf", "v", 3, {
        "py": _NO_KEYED, "go": _NO_DESTRUCT, "java": _NO_DESTRUCT, "c": _NO_DESTRUCT,
        "cpp": _NO_KEYED,
    }, {
        "js": """\
            function f(x) {
              const { k: v } = x;
              sink(v);
            }
            """,
        "rs": """\
            fn f(x: S) {
                let S { k: v } = x;
                sink(v);
            }
            """,
        "php": """\
            function f($x) {
                list("k" => $v) = $x;
                sink($v);
            }
            """,
    }),
    # W6 (cwe_22_41): a rest leaf binds the whole right-hand side.
    _row("rest_leaf", "rest", 3, {
        "go": _NO_DESTRUCT, "java": _NO_DESTRUCT, "php": _NO_REST, "c": _NO_DESTRUCT,
        "cpp": _NO_REST,
    }, {
        "js": """\
            function f(x) {
              const { a, ...rest } = x;
              sink(rest);
            }
            """,
        "py": """\
            def f(x):
                a, *rest = x
                sink(rest)
            """,
        "rs": """\
            fn f(x: [u8; 4]) {
                let [a, rest @ ..] = x;
                sink(rest);
            }
            """,
    }),
    # W6/W7 (cwe_22_27): a pattern PARAM binds each of its leaves.
    _row("pattern_param", "params", 2, {
        "py": _NO_PATTERN_PARAM, "go": _NO_PATTERN_PARAM, "java": _NO_PATTERN_PARAM,
        "php": _NO_PATTERN_PARAM, "c": _NO_PATTERN_PARAM, "cpp": _NO_PATTERN_PARAM,
    }, {
        "js": """\
            function f(_, { params }) {
              sink(params);
            }
            """,
        "rs": """\
            fn f((a, params): (u8, u8)) {
                sink(params);
            }
            """,
    }),
    # W7 (cwe_22_22): a typed parameter binds its name, never its annotation.
    _row("typed_param", "doc", 2, {"js": "has no type annotation"}, {
        "ts": """\
            function f(doc: Upload = make()) {
              sink(doc);
            }
            """,
        "py": """\
            def f(doc: Upload = make()):
                sink(doc)
            """,
        "go": """\
            func f(doc Upload) {
                sink(doc)
            }
            """,
        "java": """\
            void f(Upload doc) {
              sink(doc);
            }
            """,
        "rs": """\
            fn f(doc: Upload) {
                sink(doc);
            }
            """,
        "php": """\
            function f(Upload $doc = null) {
                sink($doc);
            }
            """,
        "c": """\
            void f(Upload *doc) {
                sink(doc);
            }
            """,
        "cpp": """\
            void f(const Upload &doc) {
                sink(doc);
            }
            """,
    }),
    # W7 (cwe_22_23): a decorator before the function leaves its parameter binding intact.
    _row("decorated_param", "name", 3, {
        "go": _NO_DECORATOR, "c": _NO_DECORATOR, "cpp": _NO_DECORATOR,
    }, {
        "js": """\
            class A { @route("/doc")
              show(name) {
                sink(name);
              }
            }
            """,
        "py": """\
            @route("/doc")
            def show(name):
                sink(name)
            """,
        "java": """\
            @GetMapping("/doc")
            String show(String name) {
              return sink(name);
            }
            """,
        "rs": """\
            #[get("/doc")]
            fn show(name: String) {
                sink(name);
            }
            """,
        "php": """\
            #[Route("/doc")]
            function show($name) {
                sink($name);
            }
            """,
    }),
    # W11: k > 1 targets bind pairwise when the RHS holds k values.
    _row("multi_target", "b", 3, {"java": _NO_MULTI, "c": _NO_MULTI}, {
        "js": """\
            function f(x, y) {
              const [a, b] = [x, y];
              sink(b);
            }
            """,
        "py": """\
            def f(x, y):
                a, b = x, y
                sink(b)
            """,
        "go": """\
            func f(x string, y string) {
                a, b := x, y
                sink(b)
            }
            """,
        "rs": """\
            fn f(x: &str, y: &str) {
                let (a, b) = (x, y);
                sink(b);
            }
            """,
        "php": """\
            function f($x, $y) {
                [$a, $b] = [$x, $y];
                sink($b);
            }
            """,
        "cpp": """\
            void f(std::pair<int, int> pr) {
                auto [a, b] = pr;
                sink(b);
            }
            """,
    }),
    # W6 (cwe_22_32): an IMPORT PAIR binds its alias.
    _row("import_pair", "rf", 2, {
        "go": _NO_ALIAS_PAIR, "java": _NO_ALIAS_PAIR, "rs": _NO_ALIAS_PAIR,
        "php": _NO_ALIAS_PAIR, "c": _NO_ALIAS_PAIR, "cpp": _NO_ALIAS_PAIR,
    }, {
        "js": """\
            import { readFile as rf } from "fs";
            function f() {
              sink(rf);
            }
            """,
        "py": """\
            from os import path as rf
            def f():
                sink(rf)
            """,
    }),
)

BY_NAME: Mapping[str, Construct] = MappingProxyType({c.name: c for c in CONSTRUCTS})


def construct_source(construct: Construct, lang: str) -> str:
    """The ``lang`` program of ``construct``; a language that lacks it skips the test with
    the reason the row's ``lacks`` gives."""
    source = construct.sources[lang]
    if source is None:
        pytest.skip(f"{language_of(lang)} {construct.lacks[lang]} ({construct.name})")
    return source


@functools.cache
def construct_model(name: str, lang: str) -> FileModel:
    """The model of construct ``name`` in ``lang``, parsed once (a model is immutable)."""
    return model_of(construct_source(BY_NAME[name], lang), lang)


def _within(model: FileModel, node: int, top: int) -> bool:
    """Whether ``top`` is ``node`` or an ancestor of it (``parent(i) < i``, §6.2)."""
    while node > top:
        node = model.parent(node)
    return node == top


def _names(model: FileModel, ident: str) -> list[int]:
    """Every NAME whose shipped text is ``ident``."""
    return [i for i in model.nodes(Kind.NAME) if model.ident(i) == ident]


def _argument_names(model: FileModel, call: int, ident: str) -> list[int]:
    callee = model.callee(call)
    return [i for i in _names(model, ident) if i != callee and _within(model, i, call)]


def use_in(model: FileModel, call: int, ident: str) -> int:
    """The first NAME ``ident`` (its shipped text: a PHP ``$x`` is ``x``) in the arguments
    of ``call``: the read a scope test resolves."""
    found = _argument_names(model, call, ident)
    assert found, f"no {ident!r} among the arguments of the call on line {model.line(call)}"
    return found[0]


def construct_use(model: FileModel, construct: Construct, head: str = "sink") -> int:
    """The read of ``construct.sink_ident`` inside the ``head(...)`` call of its program."""
    return use_in(model, call_at(model, head), construct.sink_ident)
