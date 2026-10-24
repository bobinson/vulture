"""Remove repository content from everything the prove agent emits.

The plan prompt shows the model the finding's ``file_path`` and
``code_snippet``, and a model repeats what it was shown: plan descriptions,
reflections, verdict explanations and analyze-step evidence came back
quoting the source path and the cited line. That text is streamed, and
proof_result evidence is persisted and shown with the audit. Exception text
is handled at its source (``public_error``); model-authored text cannot be,
because no rule predicts what a model will write.

What CAN be known exactly is which repository strings the agent handed the
model, so those strings are removed at the one point every event passes
through: the emitter. A source path (and its shorter suffixes and the bare
file name) becomes ``[source file]``, a quoted code line becomes
``[source excerpt]``, the scan root becomes ``[source root]``, and any
secret-shaped value is masked by the shared ``mask_secret_values``.

Only the TEXT parameters of the events are scrubbed; ``finding_id``,
``status``, ``iteration`` and the user-configured ``staging_url`` pass
through untouched. Prompts and attempt records stay raw: the model already
holds that content, and scrubbing its own history would only cost plan
quality.

One emitter per run carries EVERY finding's strings, not just the finding
being proved: cross-finding learnings are one list that reaches every later
plan prompt, so finding B's plan can quote what the model learned from A.

Any JSON shape a model answers with (array, object, nested, number, null)
is flattened to ONE string before the scrub: the strategies copy model JSON
into plan, reflection and evidence fields uncoerced, and a list-valued field
used to pass through untouched (measured: ``"analysis": ["handler in
src/payments/alpha_gateway.go ..."]`` on the live stream).

Target content is not repository content. A finding's bare file name is also
a common route (``backup.sql``, ``main.js``); on a URL of the configured
staging target, or on a route the agent actually requested (``note_route``),
the bare name is kept and the staging host is never absorbed into a
placeholder. A multi-component repository path is removed everywhere.

Stated limits (see SKILLS.md, Safety Mechanism 7): a PARAPHRASE of the code,
a code fragment below the excerpt floor or without code punctuation, a
directory or an extensionless form of the path on its own, and a secret shape
``mask_secret_values`` does not know are not caught. Paths (raw, any case,
URL-encoded once or twice, Windows-separated, or re-rooted), verbatim lines
and contiguous fragments of them with any whitespace, which are what a model
echoes, are.
"""

import functools
import re
import string
from collections import Counter
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from shared.llm.errors import mask_secret_values
from shared.transport.event_emitter import AgUiEventEmitter

FILE_PLACEHOLDER = "[source file]"
CODE_PLACEHOLDER = "[source excerpt]"
ROOT_PLACEHOLDER = "[source root]"
# Every placeholder starts with this; a word containing it is scrubbed text,
# never a route worth crawling on the target.
PLACEHOLDER_PREFIX = "[source"

# A code line must clear BOTH floors to count as an excerpt. Same floor as the
# evidence-quote verifier's default minimum (24 characters, 2 identifier
# tokens): shorter lines (`}`, `return;`, `x = 1`) occur everywhere, so
# replacing them would mangle target responses without hiding anything.
_MIN_EXCERPT_CHARS = 24
_MIN_EXCERPT_TOKENS = 2
_IDENT = re.compile(r"[A-Za-z_]\w*")
# extract_snippet numbers each row "N: code".
_ROW_NUMBER = re.compile(r"^\s*\d+:\s?")

Markers = tuple[tuple[str, str], ...]


def _components(path: str) -> list[str]:
    return [p for p in path.replace("\\", "/").split("/") if p not in ("", ".")]


def _file_name(parts: list[str]) -> list[str]:
    """The last component when it has an extension: a bare ``Makefile`` or
    ``README`` is too common a word to replace on its own."""
    return [parts[-1]] if parts and "." in parts[-1].strip(".") else []


# A path in a query string or a URL path segment arrives percent-encoded,
# and a value re-encoded by a proxy or a redirect arrives as ``%252F``. Path
# patterns are case-insensitive, so ``%2f`` needs no form of its own.
_ENCODED_SLASHES = ("%2F", "%252F")


def _encoded(forms: list[str]) -> list[str]:
    return [f.replace("/", enc) for f in forms if "/" in f for enc in _ENCODED_SLASHES]


def _path_markers(path: str) -> list[str]:
    """The path as given, every suffix of >= 2 components, the file name, and
    the percent-encoded form of each multi-component one."""
    parts = _components(path)
    forms = ["/".join(parts[i:]) for i in range(len(parts) - 1)] + _file_name(parts)
    return [path.strip(), *forms, *_encoded(forms)] if forms else []


def _is_excerpt(row: str) -> bool:
    return len(row) >= _MIN_EXCERPT_CHARS and len(_IDENT.findall(row)) >= _MIN_EXCERPT_TOKENS


def _excerpt_markers(snippet: str) -> list[str]:
    rows = (_ROW_NUMBER.sub("", row).strip() for row in snippet.splitlines())
    return [row for row in rows if _is_excerpt(row)]


def _root_marker(root: str) -> list[tuple[str, str]]:
    """A one-component root (``/srv``, ``/app``) is not a marker: it is also a
    common route prefix on the target."""
    if len(_components(root)) < 2:
        return []
    return [(form, ROOT_PLACEHOLDER) for form in (root, *_encoded([root]))]


def _joined_marker(root: str, file_path: str) -> list[tuple[str, str]]:
    """The finding's relative path joined onto the scan root."""
    if not root or not file_path or file_path.startswith("/"):
        return []
    return [(f"{root}/{file_path.removeprefix('./')}", FILE_PLACEHOLDER)]


def _ordered(pairs: Iterable[tuple[str, str]]) -> Markers:
    """Deduplicated, longest first, so a full path is replaced before the
    suffix or file name inside it."""
    merged = {marker: label for marker, label in pairs if marker}
    return tuple(sorted(merged.items(), key=lambda kv: -len(kv[0])))


def _field(finding: dict[str, Any], key: str) -> str:
    return str(finding.get(key) or "")


def repo_markers(finding: dict[str, Any], source_root: str = "") -> Markers:
    """``(string, placeholder)`` pairs for every repository string the agent
    shows the model about ``finding``, plus the scan root."""
    file_path = _field(finding, "file_path")
    root = source_root.strip().rstrip("/")
    pairs = [(m, FILE_PLACEHOLDER) for m in _path_markers(file_path)]
    pairs += [(m, CODE_PLACEHOLDER) for m in _excerpt_markers(_field(finding, "code_snippet"))]
    return _ordered(pairs + _root_marker(root) + _joined_marker(root, file_path))


def _is_word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


# An encoded form may sit right after another encoded separator
# (``%2Fopt%2Fsrc%2Fbilling...``), where the plain lookbehind sees a word char.
_PLAIN_HEAD = r"(?<![\w.-])"
_ENCODED_HEAD = r"(?:(?<![\w.-])|(?<=%2[Ff])|(?<=%252[Ff]))"


def _head(marker: str) -> str:
    """A boundary applies only on a word-character end: ``a.py`` must not
    rewrite ``data.py``; a marker that begins with ``/`` or ``(`` is already
    delimited."""
    if not _is_word(marker[0]):
        return ""
    return _ENCODED_HEAD if "%2" in marker else _PLAIN_HEAD


def _tail(marker: str) -> str:
    return r"(?!\w)" if _is_word(marker[-1]) else ""


_PIECE = re.compile(r"\w+|\S")


def _flexible(line: str) -> str:
    """A code line matched with any whitespace between its words and
    punctuation marks: a model reflows what it quotes (``f( x )`` for
    ``f(x)``)."""
    return r"\s*".join(map(re.escape, _PIECE.findall(line)))


@functools.lru_cache(maxsize=4096)
def _pattern(marker: str, label: str) -> re.Pattern[str]:
    """Compiled on first use and shared across runs: a run with 1000 findings
    holds 6000+ markers, and compiling them all up front measured 0.16 s.
    A path matches in any case (a model capitalises ``SRC/Payments/...``);
    code stays case-sensitive."""
    if label == CODE_PLACEHOLDER:
        return re.compile(f"{_head(marker)}{_flexible(marker)}{_tail(marker)}")
    return re.compile(f"{_head(marker)}{re.escape(marker)}{_tail(marker)}", re.IGNORECASE)


def _tokens(marker: str) -> list[str]:
    """The identifier tokens a text quoting ``marker`` must contain. Word-char
    ends carry a boundary, so an end token cannot be glued to a neighbour; the
    one exception is the first token of an encoded form (``%2Fsrc`` tokenises
    as ``Fsrc``), skipped."""
    tokens = _IDENT.findall(marker.casefold())
    return tokens[1:] if "%2" in marker else tokens


def _rarest(tokens: list[str], freq: Counter[str]) -> str:
    """The token fewest markers share, longest on a tie. The longest token
    alone measured 33 ms per 5 KB event when 1000 snippets shared one call
    name: every one of them became a candidate."""
    return min(tokens, key=lambda t: (freq[t], -len(t)), default="")


def _token_counts(tokens: list[list[str]]) -> Counter[str]:
    """How many markers contain each token."""
    return Counter(t for toks in tokens for t in set(toks))


def _keys(markers: Markers) -> list[str]:
    tokens = [_tokens(marker) for marker, _label in markers]
    freq = _token_counts(tokens)
    return [_rarest(toks, freq) for toks in tokens]


def _longest_first(pair: tuple[str, str]) -> int:
    return -len(pair[0])


class _MarkerIndex:
    """Markers keyed by one identifier token each (the rarest), so a scrub
    tokenises the text once and tests only the markers whose token it
    contains. Linear in
    the text, not in the markers: with 6000 markers the per-marker substring
    gate it replaces measured 5.2 ms per 5 KB event."""

    __slots__ = ("_by_key", "_keyless")

    def __init__(self, markers: Markers) -> None:
        self._by_key: dict[str, list[tuple[str, str]]] = {}
        self._keyless: list[tuple[str, str]] = []
        for pair, key in zip(markers, _keys(markers), strict=True):
            bucket = self._by_key.setdefault(key, []) if key else self._keyless
            bucket.append(pair)

    def candidates(self, text: str) -> list[tuple[str, str]]:
        # Keys are case-folded: a path marker matches in any case.
        keys = self._by_key.keys() & set(_IDENT.findall(text.casefold()))
        hits = [pair for key in keys for pair in self._by_key[key]] + self._keyless
        return sorted(hits, key=_longest_first)


# Characters a directory run can contain. ASCII on purpose: it bounds what the
# backward walk below may swallow.
# Backslash and colon cover a Windows path (``C:\\work\\repo\\``); ``%`` an
# encoded one.
_PATH_CHARS = frozenset(string.ascii_letters + string.digits + "_.-/\\:%")
_SEPARATOR_ENDS = ("/", "\\", "%2F", "%2f", "%252F", "%252f")


def _run_start(part: str) -> int:
    i = len(part)
    while i and part[i - 1] in _PATH_CHARS:
        i -= 1
    return i


def _after_origin(part: str, start: int, origins: tuple[str, ...]) -> int:
    """Where the dropped run really starts: just past a staging origin (and
    its ``/``) inside it, so ``https://staging.example.com/`` survives. The
    walk below accepts ``:`` and ``/``, and swallowed the configured host."""
    run = part[start:].casefold()
    for origin in origins:
        at = run.find(origin.casefold())
        if at >= 0:
            return start + at + len(origin) + 1
    return start


def _drop_dir_prefix(part: str, origins: tuple[str, ...] = ()) -> str:
    """Drop a directory run (``/opt/build/``) that ends right where a file
    placeholder follows. A model (or a container mount) writes a root the agent
    never saw in front of ``src/billing/x.py``; ``/opt/build/[source file]``
    would still name that root, and hand incremental discovery an ``/opt/...``
    word to crawl on the target. A backward character walk, linear in the run:
    the regex form of this (an optional ``/dir`` repetition before every marker) measured
    1.36 s on one 8 KB slash-separated string."""
    if not part.endswith(_SEPARATOR_ENDS):
        return part
    return part[:_after_origin(part, _run_start(part), origins)]


def _absorb_dir_prefixes(text: str, origins: tuple[str, ...] = ()) -> str:
    parts = text.split(FILE_PLACEHOLDER)
    if len(parts) == 1:
        return text
    heads = [_drop_dir_prefix(part, origins) for part in parts[:-1]]
    return FILE_PLACEHOLDER.join([*heads, parts[-1]])


_ROOT_TRAILERS = (*_SEPARATOR_ENDS, "-")


def _drop_path_suffix(part: str) -> str:
    """Drop the path run right after a root placeholder: another file under
    the scan root (``[source root]/src/other.py``) is repository layout the
    agent never meant to publish. A sibling directory of the root
    (``<root>-other/x.py``) names the root too, and is dropped the same way."""
    if not part.startswith(_ROOT_TRAILERS):
        return part
    i = 0
    while i < len(part) and part[i] in _PATH_CHARS:
        i += 1
    return part[i:]


def _absorb_root_suffixes(text: str) -> str:
    parts = text.split(ROOT_PLACEHOLDER)
    if len(parts) == 1:
        return text
    return ROOT_PLACEHOLDER.join([parts[0], *map(_drop_path_suffix, parts[1:])])


def clip(text: str, limit: int) -> str:
    """``text[:limit]`` that never splits a placeholder. Scrub FIRST, then
    clip: a path cut before the scrub no longer matches its marker, and the
    fragment (``src/payments/alpha_g``) was persisted."""
    start = text.rfind("[", 0, limit)
    end = text.find("]", start) + 1
    if start == -1 or end <= limit or not text.startswith(PLACEHOLDER_PREFIX, start):
        return text[:limit]
    return text[:end]


# --- Totality: every JSON shape a model may answer with becomes one string ---

# Nesting deeper than this is rendered with str(); the scrub still runs on it.
_MAX_DEPTH = 8


def _members(value: Any) -> list[Any] | None:
    if isinstance(value, dict):
        return list(value.values())
    return list(value) if isinstance(value, (list, tuple, set, frozenset)) else None


def _flatten(value: Any, depth: int = 0) -> str:
    """A model's array or object as the text of its leaves joined by ``; ``.
    The strategies copy model JSON into plan, reflection and evidence fields
    without coercion, and a non-string value skipped the scrub entirely."""
    if isinstance(value, str):
        return value
    members = _members(value)
    if members is None or depth >= _MAX_DEPTH:
        return str(value)
    return _joined(members, depth + 1)


def _joined(members: list[Any], depth: int) -> str:
    return "; ".join(_flatten(member, depth) for member in members)


def _as_items(value: Any) -> list[Any]:
    """``concerns`` as a list: a model-supplied string iterated as-is was
    scrubbed one CHARACTER at a time, which no marker can match."""
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


# --- Target routes: what the agent requested from the target is not repo content ---

_URL_REST = r"[^\s\"'<>]*"
_ROUTE = re.compile(r"(?<![\w.:/%\\-])/[^\s?#\"'<>()]*")
_SEPARATOR = re.compile(r"[/\\]|%2", re.IGNORECASE)


def _origin(url: str) -> tuple[str, ...]:
    parts = urlsplit(url.strip())
    return (f"{parts.scheme}://{parts.netloc}",) if parts.scheme and parts.netloc else ()


def _route_key(url_path: str) -> str:
    return url_path.split("?", 1)[0].split("#", 1)[0].rstrip(".,;:")


def _is_name(marker: str, label: str) -> bool:
    """A bare file name (``backup.sql``): the one marker that is also a common
    route. A multi-component path is repository layout wherever it appears."""
    return label == FILE_PLACEHOLDER and not _SEPARATOR.search(marker)


def _origin_spans(text: str, origins: tuple[str, ...]) -> list[tuple[int, int]]:
    return [m.span() for o in origins
            for m in re.finditer(re.escape(o) + _URL_REST, text, re.IGNORECASE)]


def _route_spans(text: str, routes: set[str]) -> list[tuple[int, int]]:
    return [m.span() for m in _ROUTE.finditer(text) if _route_key(m.group()) in routes]


def _keep_inside(spans: list[tuple[int, int]], label: str, match: re.Match[str]) -> str:
    inside = any(s <= match.start() and match.end() <= e for s, e in spans)
    return match.group() if inside else label


# --- Code fragments: a contiguous run of a quoted line, not just the whole line ---

# A fragment must also carry code syntax. A bare string literal from the code
# (an error message) is what the TARGET returns when the finding reproduces;
# replacing it would erase the proof, and it is public output, not source.
_CODE_SYNTAX = frozenset("()[]{}=;")
# An identifier pair shared by more lines than this is an idiom (``if err``,
# ``http.Post``), not a pointer to one snippet. Measured with 1000 synthetic
# Go findings (3 snippet lines each), per 5 KB event: built from those idioms,
# 292 ms to align without the cap and 0.58 ms with it; quoting two findings'
# lines, 46.6 ms and 1.33 ms. A fragment that contains ANY rarer pair of its
# line is still found through that pair.
_POSTING_CAP = 64


# Fragment pieces drop the backslashes that escape them, on both sides: a model
# that double-encodes its JSON writes ``os.Getenv(\"KEY\")``, and the bare
# ``\`` piece broke every run at each quote. The span still covers them.
_FRAGMENT_PIECE = re.compile(r"\\*(\w+|\S)")


def _is_ident(piece: str) -> bool:
    return piece[0].isalpha() or piece[0] == "_"


def _ident_pairs(pieces: list[str]) -> list[tuple[tuple[str, str], int]]:
    """Consecutive identifier pieces (punctuation between them skipped), with
    the index of the first. Every fragment that clears the floor holds one."""
    at = [k for k, piece in enumerate(pieces) if _is_ident(piece)]
    return [((pieces[a], pieces[b]), a) for a, b in zip(at, at[1:])]


def _common(text: list[str], line: list[str], xs: Iterable[int], ys: Iterable[int]) -> int:
    n = 0
    for x, y in zip(xs, ys):
        if text[x] != line[y]:
            break
        n += 1
    return n


def _is_fragment(pieces: list[str]) -> bool:
    return (
        sum(map(len, pieces)) >= _MIN_EXCERPT_CHARS
        and sum(map(_is_ident, pieces)) >= _MIN_EXCERPT_TOKENS
        and not _CODE_SYNTAX.isdisjoint(pieces)
    )


def _merged(spans: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if out and start <= out[-1][1]:
            out[-1] = (out[-1][0], max(end, out[-1][1]))
        else:
            out.append((start, end))
    return out


class _FragmentIndex:
    """Every quoted code line as pieces, indexed by its identifier pairs. A
    scrub splits the text into pieces once, looks up its own pairs, and grows
    each hit both ways while text and line agree (whitespace ignored, as for
    whole lines). Cost is linear in the text plus the hits."""

    __slots__ = ("_lines", "_by_pair")

    def __init__(self, lines: Iterable[str]) -> None:
        self._lines = [_FRAGMENT_PIECE.findall(line) for line in lines]
        self._by_pair: dict[tuple[str, str], list[tuple[int, int]]] = {}
        for line_id, pieces in enumerate(self._lines):
            for pair, j in _ident_pairs(pieces):
                self._by_pair.setdefault(pair, []).append((line_id, j))

    def _postings(self, pair: tuple[str, str]) -> list[tuple[int, int]]:
        hits = self._by_pair.get(pair, ())
        return list(hits) if len(hits) <= _POSTING_CAP else []

    def _run(self, text: list[str], line_id: int, a: int, j: int) -> tuple[int, int] | None:
        line = self._lines[line_id]
        back = _common(text, line, range(a - 1, -1, -1), range(j - 1, -1, -1))
        fwd = _common(text, line, range(a, len(text)), range(j, len(line)))
        run = (a - back, a + fwd)
        return run if _is_fragment(text[run[0]:run[1]]) else None

    def _hits(self, text: list[str]) -> list[tuple[int, int, int]]:
        return [(a, line_id, j) for pair, a in _ident_pairs(text)
                for line_id, j in self._postings(pair)]

    def _runs(self, text: list[str]) -> set[tuple[int, int]]:
        runs = (self._run(text, line_id, a, j) for a, line_id, j in self._hits(text))
        return {run for run in runs if run}

    def scrub(self, text: str) -> str:
        if not self._by_pair:
            return text
        runs = self._runs(_FRAGMENT_PIECE.findall(text))
        return _replace_runs(text, runs) if runs else text


def _replace_runs(text: str, runs: set[tuple[int, int]]) -> str:
    """Piece-index runs to character spans (merged), each replaced once."""
    spans = [m.span() for m in _FRAGMENT_PIECE.finditer(text)]
    chars = _merged([(spans[s][0], spans[e - 1][1]) for s, e in runs])
    for start, end in reversed(chars):
        text = text[:start] + CODE_PLACEHOLDER + text[end:]
    return text


def _code_lines(markers: Markers) -> list[str]:
    return [marker for marker, label in markers if label == CODE_PLACEHOLDER]


class ScrubbingEmitter(AgUiEventEmitter):
    """``AgUiEventEmitter`` whose free-text event fields are scrubbed."""

    __slots__ = ("_markers", "_marker_set", "_index", "_fragments", "_origins", "_routes")

    def __init__(
        self, run_id: str, markers: Markers = (), origins: tuple[str, ...] = (),
        routes: set[str] | None = None,
    ) -> None:
        super().__init__(run_id)
        self._markers = markers
        self._marker_set = frozenset(markers)
        self._index = _MarkerIndex(markers)
        self._fragments = _FragmentIndex(_code_lines(markers))
        self._origins = origins
        # Shared, by reference, with every emitter extended from this one: a
        # route requested while proving one finding is a route for the run.
        self._routes = set() if routes is None else routes

    def covers(self, markers: Markers, origins: tuple[str, ...] = ()) -> bool:
        return self._marker_set.issuperset(markers) and set(origins) <= set(self._origins)

    def note_route(self, url_path: str) -> None:
        if url_path.startswith("/"):
            self._routes.add(_route_key(url_path))

    def _protected(self, text: str) -> list[tuple[int, int]]:
        return _origin_spans(text, self._origins) + _route_spans(text, self._routes)

    def _replace(self, text: str, marker: str, label: str) -> str:
        pattern = _pattern(marker, label)
        if not _is_name(marker, label):
            return pattern.sub(label, text)
        return pattern.sub(functools.partial(_keep_inside, self._protected(text), label), text)

    def _replace_markers(self, text: str) -> str:
        # Longest first: once a full path is replaced, its suffixes and file
        # name are no longer present to be matched again.
        for marker, label in self._index.candidates(text):
            text = self._replace(text, marker, label)
        return text

    def scrub(self, text: Any) -> str:
        text = "" if text is None else _flatten(text)
        if not text:
            return text
        replaced = self._fragments.scrub(self._replace_markers(text))
        replaced = _absorb_root_suffixes(replaced)
        return mask_secret_values(_absorb_dir_prefixes(replaced, self._origins))

    def text_message(self, content: str) -> str:
        return super().text_message(self.scrub(content))

    def proof_plan_event(
        self, finding_id: str, title: str, plan_text: str, iteration: int, protocol: str = "",
    ) -> str:
        return super().proof_plan_event(
            finding_id, self.scrub(title), self.scrub(plan_text), iteration, protocol=protocol,
        )

    def proof_review_event(
        self, finding_id: str, safe: bool, concerns: list[str], iteration: int,
    ) -> str:
        return super().proof_review_event(
            finding_id, safe, [self.scrub(c) for c in _as_items(concerns)], iteration,
        )

    def proof_attempt_event(
        self, finding_id: str, reproduced: bool, evidence: str, iteration: int, protocol: str = "",
    ) -> str:
        return super().proof_attempt_event(
            finding_id, reproduced, self.scrub(evidence), iteration, protocol=protocol,
        )

    def proof_reflection_event(
        self, finding_id: str, analysis: str, suggested_approach: str, confidence: int, iteration: int,
    ) -> str:
        return super().proof_reflection_event(
            finding_id, self.scrub(analysis), self.scrub(suggested_approach), confidence, iteration,
        )

    def proof_result_event(
        self, finding_id: str, status: str, evidence: str, iterations_used: int, staging_url: str = "",
    ) -> str:
        return super().proof_result_event(
            finding_id, status, self.scrub(evidence), iterations_used, staging_url=staging_url,
        )


def _extended(
    emitter: AgUiEventEmitter, added: Markers, origins: tuple[str, ...] = (),
) -> ScrubbingEmitter:
    """``emitter`` itself when it already scrubs ``added`` for ``origins`` (no
    rebuild, so a per-finding wrap of the run-wide emitter is free), else a
    new emitter for the same run with both marker sets, both origin sets and
    the SAME noted routes."""
    if isinstance(emitter, ScrubbingEmitter) and emitter.covers(added, origins):
        return emitter
    inherited: Markers = getattr(emitter, "_markers", ())
    known: tuple[str, ...] = getattr(emitter, "_origins", ())
    return ScrubbingEmitter(
        getattr(emitter, "_run_id", ""), _ordered(inherited + added),
        tuple(dict.fromkeys(known + origins)), getattr(emitter, "_routes", None),
    )


def scrubbing(
    emitter: AgUiEventEmitter, finding: dict[str, Any] | None = None, source_root: str = "",
    target_url: str = "",
) -> ScrubbingEmitter:
    """A scrubbing emitter for the same run, adding ``finding``'s markers (and
    the scan root's) to any the given emitter already scrubs. ``target_url``
    is the staging URL the user configured: URLs on it are target content."""
    return _extended(emitter, repo_markers(finding or {}, source_root), _origin(target_url))


def scrubbing_all(
    emitter: AgUiEventEmitter, findings: Iterable[dict[str, Any]], source_root: str = "",
    target_url: str = "",
) -> ScrubbingEmitter:
    """One emitter for the whole run that scrubs EVERY finding's markers.
    Cross-finding learnings are a single list fed to every later plan prompt,
    so any finding's events can repeat what the model was shown about any
    other finding."""
    pairs = (pair for f in findings for pair in repo_markers(f, source_root))
    return _extended(emitter, _ordered(pairs), _origin(target_url))


def note_route(emitter: AgUiEventEmitter, url_path: str) -> None:
    """Record a route the agent actually requested from the target, so its
    file-name-shaped path (``/package.json``) is kept in evidence. A no-op on
    an emitter that does not scrub."""
    if isinstance(emitter, ScrubbingEmitter):
        emitter.note_route(str(url_path or ""))


def is_scrubbed(word: str) -> bool:
    """True when ``word`` contains a placeholder this module wrote."""
    return PLACEHOLDER_PREFIX in word
