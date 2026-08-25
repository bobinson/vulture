"""CWE input validation vulnerability detection skill."""

import re
from pathlib import Path
from typing import NamedTuple

from agents import function_tool
from shared.tools.file_scanner import (
    CODE_EXTENSIONS,
    COMMENT_INDICATORS,
    SCANNER_DEF_LINE,
    is_generated_file,
    is_prose_file,
    is_test_file,
    read_file_lines,
    scan_code_files,
)
from shared.tools.snippet import extract_snippet

from cwe_agent.catalog import enrich_finding

# CWE-22: Path traversal.
#
# Each pattern requires a filesystem SINK on the same line as a tainted
# source identifier. Bare `../` substrings in TS imports, scoped npm
# package names, and URL literals are not attacks and don't match.
# `..\` and `..%2f` belong to path_equivalence_check — kept out here
# to prevent double-flagging.
_TAINTED_SOURCE = (
    r"\b(?:"
    r"request|req|params|input|user|body|query|payload"
    r"|argv|args"
    r"|filename|file_name|fileName|filepath|file_path|filePath"
    r"|fname|user_file|uploaded_file|uploaded_filename"
    r"|user_filename|dest_path|dest_file"
    r")\w*"
)
PATH_TRAVERSAL_PATTERNS = [
    re.compile(
        r'(?:'
        r'os\.path\.join'
        r'|\b(?:open|Path)'
        r'|\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)'
        r'|\bfs\.(?:readFile|writeFile|stat|access|unlink)'
        r'|\b(?:ioutil\.ReadFile|os\.Open|os\.OpenFile|os\.Create)'
        r'|\bres\.(?:sendFile|download)'
        r'|\b(?:new\s+File|Files\.read(?:String|AllBytes)?|Paths\.get)'
        r')\s*\([^)]*' + _TAINTED_SOURCE,
        re.IGNORECASE,
    ),
    # Go HTTP-handler shape: ioutil.ReadFile(r.URL.Query().Get(...))
    re.compile(
        r'\b(?:ioutil\.ReadFile|os\.Open|os\.OpenFile|os\.Create)\s*\([^)]*'
        r'\b(?:r|req|c|ctx)\.\w+\('
    ),
]

SAFE_PATH_PATTERNS = re.compile(
    r"(?:os\.path\.abspath|os\.path\.realpath|os\.path\.normpath|"
    r"secure_filename|sanitize|validate|whitelist|allowed_paths|"
    r"__file__|__dir__|BASE_DIR|ROOT_DIR)",
    re.IGNORECASE,
)

# CWE-20: Improper input validation.
#
# Modern web frameworks expose request-data via several access shapes.
# Bracket-only matching missed all of:
#   - dot access:        request.args.user_id
#   - property access:   request.json
#   - method get():      request.get("user_id"), request.GET.get("u")
#   - destructured kwargs: const { id } = req.body  (TS/JS — best-effort)
NO_VALIDATION_PATTERNS = [
    # bracket access (original)
    re.compile(r'(?:request|req)\.(?:body|params|query|form|args)\s*\[', re.IGNORECASE),
    re.compile(r'(?:request|req)\.(?:GET|POST)\s*\[', re.IGNORECASE),
    re.compile(r'params\[:?\w+\]'),
    # dot-attribute access on request: request.args.foo, req.body.bar
    re.compile(r'(?:request|req)\.(?:body|params|query|form|args|GET|POST)\.\w+', re.IGNORECASE),
    # request.json (Flask), request.JSON (less common)
    re.compile(r'(?:request|req)\.json\b'),
    # request.get("name") / request.GET.get("name") method form
    re.compile(r'(?:request|req)\.(?:GET|POST|args|form|body|params|query)\.get\s*\(\s*["\']', re.IGNORECASE),
    re.compile(r'(?:request|req)\.get\s*\(\s*["\']', re.IGNORECASE),
    # JS/TS destructure of req.body / req.query / req.params
    re.compile(r'(?:const|let|var)\s*\{\s*[^}]+\}\s*=\s*(?:request|req)\.(?:body|query|params)\b', re.IGNORECASE),
]

SAFE_VALIDATION_PATTERNS = re.compile(
    r"(?:validate|sanitize|clean|escape|strip|schema|serialize|"
    r"wtforms|pydantic|marshmallow|cerberus|voluptuous|joi\.|"
    r"\.is_valid|form\.cleaned_data|isinstance\()",
    re.IGNORECASE,
)

# CWE-434: Unrestricted file upload.
#
# Two-tier:
#   STRONG patterns are upload SINKS — function calls / API references
#   that genuinely receive uploaded bytes. Match these directly.
#   WEAK patterns are bare identifier mentions of "upload" that need
#   corroboration: only fire when a STRONG pattern also appears
#   somewhere in the file. Without that corroboration, the bare
#   "upload" substring matches every JSX import, every state variable,
#   every database column name, GraphQL operation name, etc.
#
# Files we always SKIP for CWE-434:
#   - YAML / JSON / TOML metadata, schema, and config files (no upload
#     sink can be expressed declaratively)
#   - TypeScript .d.ts type-definition files
FILE_UPLOAD_STRONG = [
    # Python frameworks
    re.compile(r'\brequest\.files\b', re.IGNORECASE),
    re.compile(r'\brequest\.FILES\b'),                    # Django
    re.compile(r'\bMultiPartParser\b'),                   # Django REST framework
    re.compile(r'\bFlask-Uploads\b'),
    # Node.js libraries (real upload-handling middleware)
    re.compile(r'\bmulter\s*\(', re.IGNORECASE),          # multer({})
    re.compile(r'\bformidable\s*\(', re.IGNORECASE),      # formidable({})
    re.compile(r'\bbusboy\s*\(', re.IGNORECASE),
    re.compile(r'\bexpress-fileupload\b', re.IGNORECASE),
    re.compile(r'\b(?:upload|files|fileUpload)\.single\s*\(', re.IGNORECASE),
    re.compile(r'\b(?:upload|files|fileUpload)\.array\s*\(', re.IGNORECASE),
    re.compile(r'\b(?:upload|files|fileUpload)\.fields\s*\(', re.IGNORECASE),
    re.compile(r'\b(?:upload|files|fileUpload)\.any\s*\('),
    # Go
    re.compile(r'\b(?:r|req|c|ctx)\.FormFile\s*\('),
    re.compile(r'\bMultipartReader\s*\('),
    # HTML5 file input (raw HTML or JSX)
    re.compile(r'<input[^>]*type\s*=\s*["\']file["\']', re.IGNORECASE),
    # Multipart content type literal in code
    re.compile(r'["\']multipart/form-data["\']', re.IGNORECASE),
    # Save with filename (real disk write, not just any save())
    re.compile(r'\.save\s*\([^)]*(?:filename|file_name)', re.IGNORECASE),
    # Browser File API
    re.compile(r'\b(?:event|e|evt)\.(?:target|currentTarget|dataTransfer)\.files\b'),
    re.compile(r'\binput\.files\b'),
    re.compile(r'\bnew\s+FormData\s*\('),
    re.compile(r'\bformData\.append\s*\(\s*["\'](?:file|files|attachment|upload)', re.IGNORECASE),
    # React-dropzone
    re.compile(r'\buseDropzone\s*\(', re.IGNORECASE),
    re.compile(r'<Dropzone\b', re.IGNORECASE),
    # Formik / MUI file field
    re.compile(r'<Field[^>]*type\s*=\s*["\']file["\']', re.IGNORECASE),
    # Spring MultipartFile, Rails Active Storage
    re.compile(r'\bMultipartFile\b'),
    re.compile(r'\bhas_(?:one|many)_attached\b'),
]

# Generic mentions that need corroboration. Kept narrow.
FILE_UPLOAD_WEAK = [
    re.compile(r'\bupload\w*\s*=\s*multer\s*\(', re.IGNORECASE),
]

# File extensions where CWE-434 is structurally impossible to express
# (declarative configs, schemas, type stubs).
_NON_CODE_EXTENSIONS = frozenset({
    ".yaml", ".yml", ".json", ".toml", ".ini", ".env",
    ".d.ts",                             # TS type definitions
})

# Non-code basenames that hold metadata and trip the bare-"upload" regex
# (Hasura action declarations, DB schema column lists, etc.)
_NON_CODE_BASENAMES = frozenset({
    "actions.yaml", "metadata.yaml",
})

# Backward compat alias for tests / callers.
FILE_UPLOAD_PATTERNS = FILE_UPLOAD_STRONG + FILE_UPLOAD_WEAK

SAFE_UPLOAD_PATTERNS = re.compile(
    r"(?:allowed_extensions|content_type|file_type|mimetype|"
    r"max_size|max.?length|file.?size|content.?length|"
    r"ALLOWED_TYPES|accept=|validate|secure_filename)",
    re.IGNORECASE,
)

# CWE-611: XXE (XML External Entity)
#
# The first eight entries are Python/Java parser APIs. That left Node with ZERO
# coverage, so a TypeScript target whose own source comment reads "intentionally
# vulnerable to XXE for the related challenges" scored nothing: the parse is
# configured through libxml2 ParseOption bit flags
# (`XML_PARSE_NOENT | XML_PARSE_DTDLOAD`), a shape no Python/Java regex can see.
# The Node additions follow.
XXE_PATTERNS = [
    re.compile(r'xml\.etree\.ElementTree\.parse\('),
    re.compile(r'etree\.parse\('),
    re.compile(r'xml\.dom\.minidom\.parse\('),
    re.compile(r'xml\.sax\.parse\('),
    re.compile(r'lxml\.etree\.parse\('),
    re.compile(r'XMLReader\(\)'),
    re.compile(r'DocumentBuilder(?:Factory)?\.new'),
    re.compile(r'SAXParser(?:Factory)?\.new'),
    # libxml2 / libxml2-wasm / libxmljs parse options that switch entity
    # substitution and DTD loading ON. These flags ARE the vulnerability.
    re.compile(r'\bXML_PARSE_(?:NOENT|DTDLOAD|DTDVALID|DTDATTR)\b'),
    # Option-object form: { noent: true, dtdload: true }, { replaceEntities: true }
    re.compile(
        r'\b(?:noent|dtdload|dtdvalid|replaceEntities|resolveEntities'
        r'|expandEntities|externalEntities|loadExternalDtd)\s*:\s*true\b',
        re.IGNORECASE,
    ),
    # libxmljs / libxmljs2 parse entry points.
    re.compile(r'\b(?:libxmljs2?|libxml2?)\s*\.\s*parseXml(?:String)?\s*\('),
    re.compile(
        r'\bparseXml(?:String)?\s*\([^)]*'
        r'\b(?:noent|dtdload|replaceEntities|option)\b',
        re.IGNORECASE,
    ),
    # xml2js: parses with sax defaults and no hardening switch of its own.
    re.compile(r'\bxml2js\s*\.\s*(?:parseString(?:Promise)?|Parser)\s*\('),
    re.compile(r'\bnew\s+(?:xml2js\.)?Parser\s*\(\s*\{[^}]*explicitRoot'),
    # DOMParser: XXE-capable outside the browser sandbox (xmldom, jsdom, Deno).
    re.compile(r'\bDOMParser\s*\(\s*\)\s*\.\s*parseFromString\s*\('),
    # sax with entity expansion left permissive.
    re.compile(
        r'\bsax\s*\.\s*(?:parser|createStream)\s*\([^)]*'
        r'\bstrictEntities\s*:\s*false',
        re.IGNORECASE,
    ),
]

# Safe-XXE: explicit module imports (defusedxml) or attribute settings
# that DEFINITIVELY disable entity resolution. The previous regex
# matched any line containing the literal `resolve_entities = False`,
# but `resolve_entities = SAFE_FLAG` (where SAFE_FLAG is False) was
# missed. We accept either the literal-False form OR an obvious
# defusedxml import. Comments containing the words alone (e.g. "# safe:
# defusedxml") no longer trigger because they don't reach the regex
# without function-call shape.
SAFE_XXE_PATTERNS = re.compile(
    r"(?:"
    # Explicit safe library import or call
    r"\bimport\s+defusedxml\b"
    r"|\bfrom\s+defusedxml\b"
    r"|\bdefusedxml\.\w+\.parse\s*\("
    # Constructor with literal False / no_network=True
    r"|XMLParser\s*\([^)]*\bresolve_entities\s*=\s*False\b"
    r"|XMLParser\s*\([^)]*\bno_network\s*=\s*True\b"
    # Java SAX feature toggles
    r"|setFeature\s*\([^)]*disallow-doctype-decl[^)]*,\s*true\)"
    r"|setFeature\s*\([^)]*external-general-entities[^)]*,\s*false\)"
    r"|setFeature\s*\([^)]*external-parameter-entities[^)]*,\s*false\)"
    # Node option objects that explicitly harden the parser. A parse call whose
    # own options say `noent: false` / `strictEntities: true` is the fixed
    # configuration, so the sink patterns above must not fire on it.
    r"|(?:noent|dtdload|dtdvalid|replaceEntities|resolveEntities|expandEntities"
    r"|externalEntities|loadExternalDtd)\s*:\s*false"
    r"|strictEntities\s*:\s*true"
    r"|\bnonet\s*:\s*true"
    r")",
    re.IGNORECASE,
)

# CWE-352: Cross-Site Request Forgery (CSRF).
#
# Server-side decorator/route patterns AND modern client-side state-
# changing fetch/XHR shapes. SPAs that hit `fetch("/api", {method:
# "POST"})` without a CSRF token are now matched — previously only
# `<form method=POST>` markup was detected.
CSRF_PATTERNS = [
    # Server-side route decorators
    re.compile(r"@app\.route\([^)]*methods\s*=\s*\[.*(?:POST|PUT|DELETE|PATCH)", re.IGNORECASE),
    re.compile(r"router\.(?:post|put|delete|patch)\s*\(", re.IGNORECASE),
    re.compile(r"@(?:Post|Put|Delete|Patch)Mapping", re.IGNORECASE),
    # HTML form
    re.compile(r'<form[^>]*method\s*=\s*["\']?(?:post|put|delete|patch)', re.IGNORECASE),
    # Client-side fetch / axios / XHR with state-changing method
    re.compile(
        r'fetch\s*\([^)]*\bmethod\s*:\s*["\'](?:POST|PUT|DELETE|PATCH)["\']',
        re.IGNORECASE,
    ),
    re.compile(r'\baxios\.(?:post|put|delete|patch)\s*\(', re.IGNORECASE),
    re.compile(
        r'(?:XMLHttpRequest|xhr)\s*\.\s*open\s*\(\s*["\'](?:POST|PUT|DELETE|PATCH)["\']',
        re.IGNORECASE,
    ),
    # jQuery
    re.compile(r'\$\.(?:post|ajax)\s*\(', re.IGNORECASE),
]

SAFE_CSRF_PATTERNS = re.compile(
    r"(?:csrf|CSRFProtect|CsrfViewMiddleware|csrf_token|_token|X-CSRF|antiforgery|csurf|csrfmiddlewaretoken)",
    re.IGNORECASE,
)

# CWE-502: Deserialization of Untrusted Data
DESERIALIZATION_PATTERNS = [
    re.compile(r"pickle\.loads?\s*\("),
    re.compile(r"yaml\.(?:load|unsafe_load)\s*\("),
    re.compile(r"marshal\.loads?\s*\("),
    re.compile(r"shelve\.open\s*\("),
    re.compile(r"\bunserialize\s*\("),  # PHP
    re.compile(r"\.readObject\s*\("),  # Java ObjectInputStream
    re.compile(r"jsonpickle\.decode\s*\("),
]

SAFE_DESERIALIZE_PATTERNS = re.compile(
    r"(?:SafeLoader|safe_load|yaml\.safe_load|yaml\.CSafeLoader|trusted|allowed_classes)",
    re.IGNORECASE,
)

IMPORT_LINE = re.compile(r"^\s*(?:from|import|require|use)\s")

# ---------------------------------------------------------------------------
# Feature 0070 P7 — five reviewed additions (CWE-776, 103, 183, 646, 36).
#
# All five are emitted through one `_Rule` table + `_emit_rule`, so a new
# member costs a table row rather than a near-identical function. The
# `category=` literal in each row is what the coverage extractor reads — never
# build it with an f-string, or detection works while the attestation denies it.
# ---------------------------------------------------------------------------

_LINE_CAP = 600           # matches signatures/detector.py's cap
_LITERAL_CAP = 600        # collection-literal body budget for CWE-183


class _Rule(NamedTuple):
    """One emitted finding shape."""

    cwe: str
    category: str
    check_id: str
    severity: str
    title: str
    description: str
    recommendation: str


# ── CWE-776: recursive entity references (XML entity expansion) ──
#
# Every alternative pins the UNSAFE LITERAL rather than the property name, so
# the hardening twin (`huge_tree=False`, `FEATURE_SECURE_PROCESSING,true`,
# `SUPPORT_DTD,false`, `forbid_entities=True`, a positive expansion limit) is
# structurally unable to match. That is what keeps the rule quiet.
#
# Disjoint from XXE_PATTERNS by construction: `huge_tree` is not in the
# camelCase option list, `setExpandEntityReferences(true)` is a method call so
# the `\s*:\s*true` option form cannot see it, and the remaining properties
# appear nowhere in this skill. The one genuine collision — a
# `XML_PARSE_HUGE | XML_PARSE_NOENT` bitmask — is carved out by only running
# this check when CWE-611 did NOT claim the line (P5 row stacking).
_XEE_PATTERNS = (
    # lxml: unbounded tree growth, both the kwarg and the option-object form.
    re.compile(r"\bhuge_tree\s*=\s*True\b"),
    re.compile(r"\bhuge_tree\s*:\s*true\b", re.IGNORECASE),
    # libxml2 parse option that removes the expansion limits.
    re.compile(r"\bXML_PARSE_HUGE\b"),
    # Java DOM: entity references expanded into the tree.
    re.compile(r"\bsetExpandEntityReferences\s*\(\s*true\s*\)"),
    # JAXP secure processing off == expansion limits off. Symbol and URI forms.
    re.compile(r"FEATURE_SECURE_PROCESSING\s*,\s*false\b", re.IGNORECASE),
    re.compile(r"feature/secure-processing[\"']\s*,\s*(?:\"|')?false\b", re.IGNORECASE),
    # StAX: DTD support switched back on.
    re.compile(r"\bSUPPORT_DTD\s*,\s*true\b", re.IGNORECASE),
    # defusedxml: entity forbidding turned off.
    re.compile(r"\bforbid_entities\s*=\s*False\b"),
    # "No limit" expansion budget, as a symbol/kwarg and as a quoted property.
    re.compile(r"\bENTITY_EXPANSION_LIMIT\s*,\s*0\b"),
    re.compile(r"\bentityExpansionLimit(?:[\"'])?\s*[,:=]\s*[\"']?0\b", re.IGNORECASE),
)

# A binding that DEFINES the flag's numeric value is not a parser setting.
_XEE_CONST_DEF = re.compile(
    r"\bXML_PARSE_\w+\s*[:=]\s*(?:0x[\da-fA-F]+|\d+|1\s*<<)"
)

_XEE_RULE = _Rule(
    cwe="776",
    category="CWE-776",
    check_id="cwe.input_validation.entity_expansion",
    severity="high",
    title="Recursive XML entity expansion (XEE) not restricted",
    description="XML parser configured without entity-expansion limits",
    recommendation=(
        "Keep secure processing enabled, leave DTD support off, and do not set "
        "an unlimited entity-expansion budget (huge_tree / entityExpansionLimit=0)"
    ),
)

# ── CWE-103: Struts ValidatorForm with an incomplete validate() override ──
#
# Hard framework gate: `extends Validator(Action)?Form` appears only in Struts 1
# Validator-framework code. A subclass whose validate() never delegates to
# super.validate() silently discards every declarative validation rule.
_STRUTS_FORM = re.compile(r"\bextends\s+Validator(?:Action)?Form\b")
_STRUTS_DELEGATES = re.compile(r"\bsuper\s*\.\s*validate\s*\(|\babstract\s+class\b")
_STRUTS_VALIDATE_DEF = re.compile(
    r"\bvalidate\s*\(\s*(?:final\s+)?ActionMapping\b|\bActionErrors\s+validate\s*\("
)

_STRUTS_RULE = _Rule(
    cwe="103",
    category="CWE-103",
    check_id="cwe.input_validation.struts_incomplete_validate",
    severity="medium",
    title="Struts validate() override does not call super.validate()",
    description="ValidatorForm subclass discards its declarative validation rules",
    recommendation="Call super.validate(mapping, request) and merge the returned ActionErrors",
)

# ── Shared upload gate for CWE-183 / CWE-646 ──
#
# The bare word `upload` passes ~1.5% of a typical tree (every comment, every
# JSX import, every state variable), so it is not a gate at all. A REAL
# server-side upload API is.
_UPLOAD_API = re.compile(
    r"(?:multer\s*\(|MultipartFile|CommonsMultipartResolver|\$_FILES"
    r"|request\.files|request\.FILES|\breq\.files?\b|secure_filename"
    r"|formidable\s*\(|\bbusboy\b|\bShrine\b|CarrierWave|ActiveStorage"
    r"|\bupload\w*\s*\.\s*(?:single|array|fields|any)\s*\("
    r"|\b(?:r|req|c|ctx)\.FormFile\s*\()"
)

# Content sniffing anchored to an IMPORT / library call. The bare substring
# `file-?type` also matches the ordinary identifier `fileType`, which is
# present in virtually every upload handler — it would disable the rule
# precisely where it is supposed to fire.
_SNIFF_IMPORT = re.compile(
    r"(?:require\s*\(\s*[\"']file-type[\"']|from\s+[\"']file-type[\"']"
    r"|\bimport\s+magic\b|python-magic|filetype\.guess|magic\.from_(?:buffer|file)"
    r"|\bimghdr\b|Image\.open\s*\(|require\s*\(\s*[\"']sharp[\"']"
    r"|from\s+[\"']sharp[\"']|\bTika\b|probe-image-size|\bffprobe\b|\bclamav\b)",
    re.IGNORECASE,
)

# ── CWE-183: permissive list of allowed inputs ──
#
# The name must be an IDENTIFIER: no `\s` inside it, or the pattern degrades
# into a prose matcher ("Accepted formats: ..."). The assignment must open a
# collection literal on the same line, which also rejects feature switches
# (`allowExtension: true`).
_ALLOWLIST_NAME = re.compile(
    r"\b(?:allow(?:ed)?|permitted|accepted|whitelist(?:ed)?)[_-]?(?:file[_-]?)?"
    r"(?:ext(?:ension)?s|types?|mime(?:[_-]?types?)?|formats?)\b\s*[:=]\s*[\[\{\(]",
    re.IGNORECASE,
)

# Deny-list naming inverts the meaning; the syntax/highlight/icon families are
# lists of LANGUAGES, not of accepted uploads.
_ALLOWLIST_EXCLUDE = re.compile(
    r"\b(?:deny|denied|block(?:ed)?|forbid(?:den)?|reject(?:ed)?|disallow(?:ed)?"
    r"|banned|blacklist(?:ed)?|lang(?:uage)?s?|syntax|highlight|icons?|themes?"
    r"|monaco|prism|codemirror|shiki)\b",
    re.IGNORECASE,
)

# Members that execute or carry active content when served back.
_DANGEROUS_MEMBER = re.compile(
    r"[\"']\.?(?:x?html?|xht|svgz?|php\d?|phtml|phar|jspx?|aspx?|jsx?|mjs|cjs"
    r"|jar|war|ear|exe|dll|bat|cmd|com|cgi|pl|py|rb|sh|bash|ps1|vbs|swf|hta)[\"']"
    r"|[\"'](?:text/html|image/svg\+xml|application/(?:x-httpd-php|javascript"
    r"|x-msdownload|x-sh|x-msdos-program)|\*/\*)[\"']",
    re.IGNORECASE,
)

_ALLOWLIST_RULE = _Rule(
    cwe="183",
    category="CWE-183",
    check_id="cwe.input_validation.permissive_allowlist",
    severity="medium",
    title="Upload allow-list admits an executable or active file type",
    description="Allow-list of accepted upload types includes an active-content member",
    recommendation=(
        "Remove executable/active types from the allow-list, verify content by "
        "sniffing the bytes, and serve uploads from a non-executing location"
    ),
)

# ── CWE-646: reliance on the supplied file name / extension ──
#
# Server-side accessors ONLY. `file.name` / `file.type` are the browser File
# API: `if (!file.type.startsWith('image/')) setError(...)` in a React upload
# component is ubiquitous and is not a server-side accept decision.
_UPLOAD_NAME_ACCESSOR = re.compile(
    r"(?:\boriginalname\b|\boriginalFilename\b|getOriginalFilename\s*\(\s*\)"
    r"|\$_FILES\[[^\]]*\]\[\s*[\"'](?:name|type)"
    r"|request\.files\[[^\]]*\]\.filename"
    r"|\bfile\s*\.\s*(?:mimetype|content_type)\b)",
    re.IGNORECASE,
)

# The extension / declared type is DERIVED from that name on the same line.
_EXT_DECISION = re.compile(
    r"(?:\.lastIndexOf\s*\(\s*[\"']\.[\"']"
    r"|\.r?split\s*\(\s*[\"']\.[\"']"
    r"|os\.path\.splitext\s*\("
    r"|\bpathinfo\s*\("
    r"|\bextname\s*\("
    r"|\bgetExtension\s*\("
    r"|\.endsWith\s*\(\s*[\"']\."
    r"|\.startsWith\s*\(\s*[\"'][\w.+-]+/)",
    re.IGNORECASE,
)

# The derived value must drive a rejection / branch, so extraction used only to
# build a storage name or a display label does not fire.
_REJECT_BRANCH = re.compile(
    r"\bif\s*[\(\s]|\breturn\b|\bthrow\b|\braise\b|\babort\s*\(|\bcb\s*\(|\bnext\s*\("
)

# A random rename means the supplied name is not the security decision.
_SAFE_RENAME = re.compile(r"secure_filename|\buuid|randomUUID|\bnanoid\b", re.IGNORECASE)

_FILENAME_RULE = _Rule(
    cwe="646",
    category="CWE-646",
    check_id="cwe.input_validation.filename_reliance",
    severity="medium",
    title="Upload accepted on the strength of its supplied file name",
    description="Accept/reject decision derived from the client-supplied extension",
    recommendation=(
        "Decide on sniffed content (file-type, python-magic, Tika), store under a "
        "generated name, and treat the supplied extension as untrusted metadata"
    ),
)

# ── CWE-36: absolute path traversal via a substitution sanitiser ──
#
# ONLY the substitution shapes, which are defective by construction: stripping
# the `..` token does nothing to an absolute path and is also defeated by
# `....//`. Every membership / startsWith / includes / Contains / HasPrefix arm
# is deliberately absent — measured 46 anchor hits, 4 survivors, 4/4 false,
# because 72% of them sit beside path.relative / filepath.Rel / os.path.relpath,
# which is a CORRECT containment defence that no regex can tell apart from an
# incomplete one.
_ABS_SANITISERS = (
    # JS/TS: .replace('../','') / .replaceAll(/\.\.\//g,'')
    re.compile(
        r"\.\s*replace(?:All)?\s*\(\s*(?:[\"']\.\.[/\\]?[\"']"
        r"|/(?:\\\.){2}[/\\]?/g\w*)\s*,\s*(?:[\"'][\"']|``)\s*\)"
    ),
    # Python: re.sub(r'\.\./', '', ...). NOTE the shared `SCANNER_DEF_LINE`
    # guard (`=\s*re\.`) swallows the `cleaned = re.sub(...)` assignment form,
    # so this arm is reachable only when the call is nested (e.g. inside the
    # sink). Narrowing that shared guard would expose every existing pattern in
    # this skill to `x = re.<anything>` lines, which is not a trade this item
    # licenses.
    re.compile(r"re\.sub\s*\(\s*r?[\"'](?:\\?\.){2}[/\\]?[\"']\s*,\s*[\"'][\"']"),
    # Python / Java: .replace('..', '')
    re.compile(r"\.\s*replace\s*\(\s*[\"']\.\.[/\\]?[\"']\s*,\s*[\"'][\"']\s*\)"),
    # Go: strings.ReplaceAll(name, "..", "")
    re.compile(r"strings\.ReplaceAll\s*\([^,]{1,60},\s*\"\.\.[/\\]?\"\s*,\s*\"\"\s*\)"),
    # PHP: str_replace('..', '', $p)
    re.compile(r"str_replace\s*\(\s*[\"']\.\.[/\\]?[\"']\s*,\s*[\"'][\"']"),
    # Ruby: .gsub('..', '')
    re.compile(r"\.\s*g?sub\s*\(\s*[\"']\.\.[/\\]?[\"']\s*,\s*[\"'][\"']\s*\)"),
)

# Any canonicalisation / containment / basename idiom in the enclosing window
# means the absolute case is already handled. Mandatory: without it the rule is
# 0/4 precise.
_PATH_CANONICALISERS = re.compile(
    r"(?:path(?:\.(?:posix|win32))?\.relative\s*\(|filepath\.Rel\s*\("
    r"|os\.path\.relpath\s*\(|\.relativize\s*\(|realpath|os\.path\.abspath"
    r"|filepath\.Abs|\.resolve\s*\(|toRealPath|isAbs|isAbsolute|is_absolute"
    r"|os\.path\.isabs|commonpath|commonprefix|basename|filepath\.Base"
    r"|secure_filename)",
    re.IGNORECASE,
)

# A repeat-until-stable strip is a different (and much stronger) construct.
_STRIP_LOOP = re.compile(
    r"^\s*(?:\}\s*)?(?:while|until|do)\b|^\s*for\s*\(", re.MULTILINE
)

# Narrowed sink set: the bare `open|Path` arms CWE-22 uses are excluded, and the
# PHP/Ruby entries are what make arms (d)/(e) reachable rather than dead code.
_ABS_SINKS = re.compile(
    r"(?:os\.path\.join|\bopen\s*\(|fs\.(?:readFile|writeFile|createReadStream"
    r"|createWriteStream)|res\.(?:sendFile|download)|os\.Open|os\.Create"
    r"|ioutil\.ReadFile|Files\.read|Paths\.get|new\s+File"
    r"|\bfopen\s*\(|\bfile_(?:get|put)_contents\s*\(|\breadfile\s*\("
    r"|\bmove_uploaded_file\s*\(|\bFile\.(?:open|read|write)\s*\(|\bIO\.read\s*\()"
)

_ABS_TRAVERSAL_RULE = _Rule(
    cwe="36",
    category="CWE-36",
    check_id="cwe.input_validation.absolute_path_traversal",
    severity="high",
    title="Path sanitiser strips '..' without rejecting absolute paths",
    description="Substitution sanitiser leaves absolute paths (and '....//') intact",
    recommendation=(
        "Resolve the path and require containment (os.path.relpath / "
        "filepath.Rel / path.relative) instead of deleting '..' substrings"
    ),
)


# ---------------------------------------------------------------------------
# Feature 0070 P8 — two reviewed additions (CWE-23, CWE-73).
#
# Both are path rows, so both join the single-claim chain in `_claim_path_row`:
# CWE-36 > CWE-23 > CWE-73 > CWE-22, at most one row per line. None of those
# four is an ancestor of another except CWE-22 (parent of 23 and 36), so the
# generic line-stack collapse cannot be relied on to remove the duplicates —
# the chain has to.
# ---------------------------------------------------------------------------

# ── CWE-23: relative path traversal via an archive entry name ("zip slip") ──
#
# The destination is built from a name the ARCHIVE controls, so `../` inside an
# entry escapes the extraction root. Three gates, all load-bearing:
#
#   (1) the file must use an archive library. Without it the identical line
#       shape (`readFile('assets/i18n/' + fileName)` inside a `readdir` loop)
#       is an ordinary walk over a server-owned directory — measured, and the
#       exact false positive this gate exists to remove;
#   (2) the name must be an archive-entry accessor, or a variable bound from
#       one somewhere in the same file (extraction loops nearly always rebind
#       `entry.path` to a local before using it);
#   (3) no containment idiom in the surrounding window — a canonicalise-then-
#       prefix check, a relativize, or a basename reduction is the correct
#       defence and must not be reported as the weakness.
_ARCHIVE_LIB = re.compile(
    r"(?:\bunzipper\b|\badm[-_]zip\b|\byauzl\b|\bjszip\b|node-stream-zip"
    r"|extract-zip|\bdecompress\b|\barchiver\b|\bzipfile\b|\btarfile\b"
    r"|ZipInputStream|ZipArchiveInputStream|TarArchiveInputStream|\bZipFile\b"
    r"|archive/zip|archive/tar)",
    re.IGNORECASE,
)

_ENTRY_NAME_SRC = (
    r"\b(?:entry|zip_?entry|tar_?entry|archive_?entry|member|tarinfo)\w*"
    r"\s*\.\s*(?:path|name|filename|file_?name|getName\s*\(\s*\))"
)
_ENTRY_ACCESSOR = re.compile(_ENTRY_NAME_SRC, re.IGNORECASE)

# `const fileName = entry.path` / `String n = entry.getName();` — the accessor
# must sit immediately right of the `=`, so `target = os.path.join(dest,
# member.name)` binds nothing (that line is already the finding).
_ENTRY_BIND = re.compile(
    r"\b(\w+)\s*(?::[^=\n]{1,40})?=\s*" + _ENTRY_NAME_SRC, re.IGNORECASE
)

_ARCHIVE_SINK = re.compile(
    r"(?:\bpath(?:\.(?:posix|win32))?\.(?:join|resolve)\s*\(|\bos\.path\.join\s*\("
    r"|\bfilepath\.Join\s*\(|\bPaths\.get\s*\(|\bnew\s+File\s*\("
    r"|\bopen\s*\(|\bcreate(?:Read|Write)Stream\s*\(|\bwriteFile(?:Sync)?\s*\("
    r"|\bcopyFile(?:Sync)?\s*\(|\bFileOutputStream\s*\()"
)

# Shared by CWE-23 and CWE-73: the untrusted component is contained, made
# relative, or reduced to a bare name. Either way the path cannot escape.
_PATH_CONTAINMENT = re.compile(
    r"(?:\.startsWith\s*\(|\bstartswith\s*\(|\bHasPrefix\s*\("
    r"|path(?:\.(?:posix|win32))?\.relative\s*\(|os\.path\.relpath\s*\("
    r"|filepath\.Rel\s*\(|\bcommonpath\s*\(|is_within_directory"
    r"|\bbasename\s*\(|filepath\.Base\s*\(|\.relativize\s*\("
    r"|secure_filename|\bfilter\s*=\s*[\"']?data)",
    re.IGNORECASE,
)

_REL_TRAVERSAL_RULE = _Rule(
    cwe="23",
    category="CWE-23",
    check_id="cwe.input_validation.archive_entry_traversal",
    severity="high",
    title="Extraction path built from an archive-controlled entry name",
    description="Archive entry name reaches a path sink with no containment check",
    recommendation=(
        "Reduce the entry name to its basename, or resolve the destination and "
        "require it to stay under the extraction root before writing"
    ),
)

# ── CWE-73: external control of file name or path ──
#
# A DIRECT request accessor inside a path builder. Direct only: allowing a
# variable indirection would reduce this to the loose identifier list CWE-22
# already carries, and CWE-22's rows are the noise gauge for this file.
#
# The absence of an I/O sink on the line is what separates the two. Once bytes
# are read or written on the same line the weakness is the traversal itself
# (CWE-22); with only a builder present, all that is demonstrable is that the
# path is externally controlled.
_PATH_BUILDER = re.compile(
    r"(?:\bpath(?:\.(?:posix|win32))?\.(?:join|resolve|normalize)\s*\("
    r"|\bos\.path\.(?:join|abspath|realpath|normpath)\s*\("
    r"|\bfilepath\.(?:Join|Abs|Clean)\s*\("
    r"|\bPaths\.get\s*\(|\bnew\s+File\s*\()"
)

_REQ_ACCESSOR = re.compile(
    r"(?:\b(?:req|request)\s*\.\s*"
    r"(?:body|query|params|form|files|cookies|headers|args|GET|POST|FILES)\b"
    r"|\$_(?:GET|POST|REQUEST|COOKIE|FILES)\s*\["
    r"|\bgetParameter\s*\(|\bgetHeader\s*\("
    r"|\b(?:r|req|c|ctx)\.(?:URL\.Query\(\)\.Get|FormValue|PostFormValue"
    r"|Param|Query)\s*\()"
)

_IO_SINK = re.compile(
    r"(?:\bopen\s*\(|\bfopen\s*\(|\bfs\.\w+\s*\(|\breadFile(?:Sync)?\s*\("
    r"|\bwriteFile(?:Sync)?\s*\(|\bcreate(?:Read|Write)Stream\s*\("
    r"|\bres\.(?:sendFile|download)\s*\(|\bsend_?[Ff]ile\s*\("
    r"|\bos\.(?:Open|OpenFile|Create|ReadFile|WriteFile)\s*\("
    r"|\bioutil\.(?:Read|Write)File\s*\(|\bFiles\.(?:read|write)\w*\s*\("
    r"|\bnew\s+File(?:Input|Output)Stream\s*\()"
)

_EXTERNAL_PATH_RULE = _Rule(
    cwe="73",
    category="CWE-73",
    check_id="cwe.input_validation.external_path_control",
    severity="high",
    title="File path built directly from request data",
    description="Path builder fed a request accessor with no name reduction",
    recommendation=(
        "Map the request value through an allow-list or reduce it to a basename, "
        "then resolve it and confirm containment under the intended root"
    ),
)


class _FileCtx(NamedTuple):
    """Per-file facts the P7/P8 rules gate on, computed once."""

    file_path: Path
    lines: tuple[str, ...]
    text: str
    upload_api: bool
    sniffing: bool
    archive: bool
    entry_names: re.Pattern | None


def _archive_entry_names(text: str) -> re.Pattern | None:
    """Alternation over local names bound from an archive-entry accessor."""
    names = {m.group(1) for m in _ENTRY_BIND.finditer(text)}
    if not names:
        return None
    return re.compile(r"\b(?:" + "|".join(sorted(map(re.escape, names))) + r")\b")


def _build_context(file_path: Path, lines: tuple[str, ...]) -> _FileCtx:
    """Collect the file-level gates for the P7/P8 rules."""
    text = "\n".join(lines)
    archive = bool(_ARCHIVE_LIB.search(text))
    return _FileCtx(
        file_path=file_path,
        lines=lines,
        text=text,
        upload_api=bool(_UPLOAD_API.search(text)),
        sniffing=bool(_SNIFF_IMPORT.search(text)),
        archive=archive,
        entry_names=_archive_entry_names(text) if archive else None,
    )


def _matches(patterns: tuple[re.Pattern, ...], line: str) -> bool:
    """True when any pattern matches the line."""
    return any(p.search(line) for p in patterns)


def _window_text(
    lines: tuple[str, ...], line_num: int, before: int, after: int
) -> str:
    """Join the lines around ``line_num`` (1-indexed, inclusive)."""
    start = max(0, line_num - 1 - before)
    end = min(len(lines), line_num + after)
    return "\n".join(lines[start:end])


def _emit_rule(
    rule: _Rule, ctx_path: Path, line_num: int, lines: tuple[str, ...],
    findings: list[dict],
) -> None:
    """Append one enriched finding for ``rule``."""
    finding = {
        "severity": rule.severity,
        "check_id": rule.check_id,
        "category": rule.category,
        "title": rule.title,
        "description": f"{rule.description} at line {line_num}",
        "file_path": str(ctx_path),
        "line_start": line_num,
        "line_end": line_num,
        "recommendation": rule.recommendation,
        "code_snippet": extract_snippet(lines, line_num),
    }
    findings.append(enrich_finding(finding, rule.cwe))


def check_input_validation(source_path: str) -> dict:
    """Check for CWE input validation vulnerabilities.

    Args:
        source_path: Path to source directory.

    Returns:
        Dict with 'findings' list of input validation vulnerabilities.
    """
    findings: list[dict] = []

    for file_path in scan_code_files(source_path):
        if not _skip_file(file_path):
            _analyze_file(file_path, findings)

    return {"findings": findings}


def _skip_file(file_path: Path) -> bool:
    """Files whose contents are not executable source for this skill.

    The prose arm is the P7 guard: this skill reads ``default_extensions()``,
    which includes ``.md/.rst/.adoc/.txt``, and ``COMMENT_INDICATORS`` cannot
    match markdown body text — so a hardening guide that only *condemns* an
    option reads as executable source and becomes a finding.
    """
    return (
        is_generated_file(file_path)
        or is_test_file(file_path)
        or is_prose_file(file_path)
    )


def _analyze_file(file_path: Path, findings: list[dict]) -> None:
    """Analyze a file for input validation patterns."""
    lines = read_file_lines(file_path)
    if lines is None:
        return
    ctx = _build_context(file_path, lines)
    _check_struts_validate(ctx, findings)
    for line_num, line in enumerate(lines, start=1):
        if COMMENT_INDICATORS.match(line):
            continue
        if IMPORT_LINE.match(line):
            continue
        if SCANNER_DEF_LINE.search(line):
            continue
        _analyze_line(ctx, line, line_num, findings)


def _analyze_line(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> None:
    """Run every line-scoped check, honouring the child-wins suppressions.

    Skill findings are not deduplicated against each other (P5), so the
    suppressions are explicit. The four path rules share one claim chain, and
    CWE-73 additionally takes the line from its CWE-20 parent — a line whose
    path is provably request-controlled says strictly more than "input was not
    validated here". CWE-611 keeps a line that also names an expansion flag.
    """
    path, lines = ctx.file_path, ctx.lines
    if _claim_path_row(ctx, line, line_num, findings) != "73":
        _check_no_validation(path, line, line_num, lines, findings)
    _check_file_upload(path, line, line_num, lines, findings)
    if not _check_xxe(path, line, line_num, lines, findings):
        _check_entity_expansion(ctx, line, line_num, findings)
    _check_csrf(path, line, line_num, lines, findings)
    _check_deserialization(path, line, line_num, lines, findings)
    _check_permissive_allowlist(ctx, line, line_num, findings)
    _check_filename_reliance(ctx, line, line_num, findings)


# ---------------------------------------------------------------------------
# Feature 0070 P7 checks
# ---------------------------------------------------------------------------


def _check_entity_expansion(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> None:
    """Check for CWE-776 recursive XML entity expansion (XEE)."""
    if _XEE_CONST_DEF.search(line):
        return
    if not _matches(_XEE_PATTERNS, line):
        return
    _emit_rule(_XEE_RULE, ctx.file_path, line_num, ctx.lines, findings)


def _first_match_line(lines: tuple[str, ...], pattern: re.Pattern) -> int:
    """1-indexed line of the first match, or 0 when there is none."""
    for idx, line in enumerate(lines, start=1):
        if pattern.search(line):
            return idx
    return 0


def _struts_incomplete(ctx: _FileCtx) -> bool:
    """True for a Struts ValidatorForm subclass that never delegates upward."""
    if ctx.file_path.suffix.lower() != ".java":
        return False
    return bool(_STRUTS_FORM.search(ctx.text)) and not _STRUTS_DELEGATES.search(ctx.text)


def _check_struts_validate(ctx: _FileCtx, findings: list[dict]) -> None:
    """Check for CWE-103 Struts incomplete validate(). One row per file."""
    if not _struts_incomplete(ctx):
        return
    line_num = _first_match_line(ctx.lines, _STRUTS_VALIDATE_DEF)
    if line_num:
        _emit_rule(_STRUTS_RULE, ctx.file_path, line_num, ctx.lines, findings)


def _upload_rule_applies(ctx: _FileCtx, line: str) -> bool:
    """Gate shared by CWE-183 / CWE-646: real upload API, code file, sane line."""
    return (
        ctx.upload_api
        and ctx.file_path.suffix.lower() in CODE_EXTENSIONS
        and len(line) <= _LINE_CAP
    )


def _literal_text(lines: tuple[str, ...], line_num: int, open_col: int) -> str:
    """Body of the collection literal opened at ``open_col`` (1-indexed)."""
    head = lines[line_num - 1][open_col - 1:]
    tail = "\n".join(lines[line_num:min(len(lines), line_num + 9)])
    body = f"{head}\n{tail}"[:_LITERAL_CAP]
    return body.split("]")[0].split("}")[0].split(")")[0]


def _allowlist_hit(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """True when an allow-list literal on this line admits active content."""
    match = _ALLOWLIST_NAME.search(line)
    if match is None or _ALLOWLIST_EXCLUDE.search(line):
        return False
    body = _literal_text(ctx.lines, line_num, match.end())
    return bool(_DANGEROUS_MEMBER.search(body))


def _check_permissive_allowlist(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> None:
    """Check for CWE-183 permissive list of allowed inputs."""
    if not _upload_rule_applies(ctx, line):
        return
    if _allowlist_hit(ctx, line, line_num):
        _emit_rule(_ALLOWLIST_RULE, ctx.file_path, line_num, ctx.lines, findings)


def _filename_reliance_hit(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """True when a supplied file name drives an accept/reject decision."""
    if not _UPLOAD_NAME_ACCESSOR.search(line) or not _EXT_DECISION.search(line):
        return False
    if _SAFE_RENAME.search(line):
        return False
    return bool(_REJECT_BRANCH.search(_window_text(ctx.lines, line_num, 0, 1)))


def _check_filename_reliance(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> None:
    """Check for CWE-646 reliance on the supplied file name / extension."""
    if ctx.sniffing or not _upload_rule_applies(ctx, line):
        return
    if _filename_reliance_hit(ctx, line, line_num):
        _emit_rule(_FILENAME_RULE, ctx.file_path, line_num, ctx.lines, findings)


def _abs_traversal_hit(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """True for a '..'-stripping sanitiser feeding a filesystem sink."""
    if len(line) > _LINE_CAP or _canonicaliser_near(ctx.lines, line_num):
        return False
    return _matches(_ABS_SANITISERS, line) and _sink_near(ctx.lines, line_num)


def _canonicaliser_near(lines: tuple[str, ...], line_num: int) -> bool:
    """True when a correct containment/canonicalisation defence is in scope."""
    if _PATH_CANONICALISERS.search(_window_text(lines, line_num, 12, 12)):
        return True
    return bool(_STRIP_LOOP.search(_window_text(lines, line_num, 2, 0)))


def _sink_near(lines: tuple[str, ...], line_num: int) -> bool:
    """True when a narrowed filesystem sink follows within three lines."""
    return bool(_ABS_SINKS.search(_window_text(lines, line_num, 0, 3)))


def _check_absolute_traversal(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> bool:
    """Check for CWE-36 absolute path traversal. True when it claimed the line."""
    if not _abs_traversal_hit(ctx, line, line_num):
        return False
    _emit_rule(_ABS_TRAVERSAL_RULE, ctx.file_path, line_num, ctx.lines, findings)
    return True


def _path_frame_ok(ctx: _FileCtx, line: str, line_num: int, span: int) -> bool:
    """Shared tail for both P8 path rules.

    A sane line length, and no containment / name-reduction idiom within
    ``span`` lines either side — one window check, two callers, so the
    "already defended" carve-out cannot drift apart between them.
    """
    if len(line) > _LINE_CAP:
        return False
    return not _PATH_CONTAINMENT.search(_window_text(ctx.lines, line_num, span, span))


def _rel_traversal_hit(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """True for an extraction path built from an archive-controlled name."""
    if not (ctx.archive and _ARCHIVE_SINK.search(line) and _entry_name_on(ctx, line)):
        return False
    return _path_frame_ok(ctx, line, line_num, 8)


def _entry_name_on(ctx: _FileCtx, line: str) -> bool:
    """True when the line names an archive entry, directly or via a binding."""
    if _ENTRY_ACCESSOR.search(line):
        return True
    return bool(ctx.entry_names and ctx.entry_names.search(line))


def _check_relative_traversal(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> bool:
    """Check for CWE-23 zip-slip. True when it claimed the line."""
    if not _rel_traversal_hit(ctx, line, line_num):
        return False
    _emit_rule(_REL_TRAVERSAL_RULE, ctx.file_path, line_num, ctx.lines, findings)
    return True


def _external_path_hit(ctx: _FileCtx, line: str, line_num: int) -> bool:
    """True for a path builder fed a direct request accessor, no I/O in sight."""
    if _IO_SINK.search(line) or not _PATH_BUILDER.search(line):
        return False
    if not _REQ_ACCESSOR.search(line):
        return False
    return _path_frame_ok(ctx, line, line_num, 2)


def _check_external_path(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> bool:
    """Check for CWE-73 external path control. True when it claimed the line."""
    if not _external_path_hit(ctx, line, line_num):
        return False
    _emit_rule(_EXTERNAL_PATH_RULE, ctx.file_path, line_num, ctx.lines, findings)
    return True


def _claim_path_row(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> str:
    """Emit at most one path row per line; return its cwe id, or ``""``.

    Order is most-specific-first: CWE-36 (absolute) > CWE-23 (archive-relative)
    > CWE-73 (externally controlled, no sink) > CWE-22 (traversal to a sink).
    """
    for cwe, check in _PATH_CLAIMS:
        if check(ctx, line, line_num, findings):
            return cwe
    return ""


def _check_path_traversal(
    ctx: _FileCtx, line: str, line_num: int, findings: list[dict]
) -> bool:
    """Check for CWE-22 path traversal. True when it claimed the line."""
    file_path, lines = ctx.file_path, ctx.lines
    if SAFE_PATH_PATTERNS.search(line):
        return False
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.path_traversal",
                "category": "CWE-22",
                "title": "Potential path traversal",
                "description": f"User-controlled path input at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use os.path.realpath and validate against allowed base directory",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "22"))
            return True
    return False


# Most-specific-first. Declared after the members so the table holds the real
# functions, and so adding a path rule costs one row rather than another branch
# in `_claim_path_row`.
_PATH_CLAIMS = (
    ("36", _check_absolute_traversal),
    ("23", _check_relative_traversal),
    ("73", _check_external_path),
    ("22", _check_path_traversal),
)


# Names BOUND on a line: `const { a, b } = ...`, `const x = ...`, `let y = ...`,
# `x, y = ...`. Used to tie a downstream guard to THIS extraction.
_BOUND_NAMES = re.compile(
    r"(?:const|let|var)\s*\{([^}]{0,200})\}"
    r"|(?:const|let|var)\s+([A-Za-z_$][\w$]{0,63})\s*="
    r"|^\s*([A-Za-z_$][\w$]{0,63})\s*="
)

# A guard SHAPE: a falsy/emptiness check, a regex test, a validator call, or a
# throw. Kept separate from SAFE_VALIDATION_PATTERNS, which is a vocabulary of
# validation LIBRARIES rather than of guard syntax.
_GUARD_SHAPE = re.compile(
    r"if\s*\(\s*!"
    r"|if\s*\([^)]{0,120}(?:===|!==|==|!=)\s*(?:undefined|null|\"\"|'')"
    r"|\.test\s*\("
    r"|\.(?:parse|safeParse|validateSync|validate)\s*\("
    r"|\bthrow\s+new\s+\w{0,48}(?:Error|Exception)"
    r"|\.(?:length|trim)\s*(?:===|!==|<|>|<=|>=)"
)

# How far AHEAD to look for the guard. Measured: on one real target 80 of 102
# CWE-20 rows had their guard within 25 lines; 30 covers that with headroom
# and is still bounded (this is a line-window walk, not a regex quantifier).
_GUARD_LOOKAHEAD = 30


def _bound_names(line: str) -> set[str]:
    """Identifiers this line binds, including destructured ones."""
    out: set[str] = set()
    for braced, single, bare in _BOUND_NAMES.findall(line):
        if braced:
            for part in braced.split(","):
                name = part.split(":")[-1].split("=")[0].strip()
                if name.isidentifier():
                    out.add(name)
        for name in (single, bare):
            if name and name.isidentifier():
                out.add(name)
    return out


def _guarded_downstream(lines: list[str], line_num: int, names: set[str]) -> bool:
    """True if a guard REFERENCING one of ``names`` follows within the window.

    Requiring the name is what keeps this from excusing an extraction merely
    because some unrelated variable is checked nearby.
    """
    if not names:
        return False
    end = min(len(lines), line_num + _GUARD_LOOKAHEAD)
    for text in lines[line_num:end]:
        if not _GUARD_SHAPE.search(text):
            continue
        if any(re.search(rf"\b{re.escape(n)}\b", text) for n in names):
            return True
    return False


def _check_no_validation(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-20 improper input validation."""
    # Check surrounding context for validation
    context_start = max(0, line_num - 4)
    context_end = min(len(lines), line_num + 3)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_VALIDATION_PATTERNS.search(context):
        return
    for pattern in NO_VALIDATION_PATTERNS:
        if pattern.search(line):
            # The commonest real shape is extract-then-guard, and the 7-line
            # context above cannot see it. Look ahead for a guard that names a
            # value bound HERE (see _guarded_downstream for why the name
            # matters).
            #
            # Evaluated AFTER the pattern match, not before: this is a
            # per-candidate cost, and hoisting it above the loop made every
            # scanned line pay a regex findall plus a 30-line window walk to
            # decide something no pattern was going to report anyway.
            if _guarded_downstream(lines, line_num, _bound_names(line)):
                return
            finding = {
                "severity": "medium",
                "check_id": "cwe.input_validation.missing_validation",
                "category": "CWE-20",
                "title": "Missing input validation",
                "description": f"User input used without validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate and sanitize all user input before processing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "20"))
            return


def _check_file_upload(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-434 unrestricted file upload.

    Only fires on real upload SINKS (multer/formidable/req.files etc.),
    not on bare identifier mentions of the substring 'upload'. Skips
    declarative metadata files (YAML/JSON schemas, GraphQL action
    declarations, DB column listings) where CWE-434 cannot be expressed.
    """
    # Skip metadata / declarative files entirely.
    suffix = file_path.suffix.lower()
    if suffix in _NON_CODE_EXTENSIONS:
        return
    if file_path.name in _NON_CODE_BASENAMES:
        return
    # Skip TypeScript .d.ts files (suffix is just ".ts" but name ends ".d.ts").
    if file_path.name.endswith(".d.ts"):
        return

    # Check surrounding context for upload safeguards.
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_UPLOAD_PATTERNS.search(context):
        return

    # Only flag on a STRONG sink match. Bare-identifier "upload" mentions
    # in JSX, imports, or state-variable names no longer trigger.
    for pattern in FILE_UPLOAD_STRONG:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.unrestricted_upload",
                "category": "CWE-434",
                "title": "Unrestricted file upload",
                "description": f"File upload without type/size validation at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Validate file type, extension, size, and content before saving",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "434"))
            return


def _check_xxe(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> bool:
    """Check for CWE-611 XML external entity.

    Returns True when a row was emitted, so the CWE-776 child can stand down
    rather than stack a second row on the same line (P5).
    """
    # Check surrounding context for XXE protections
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_XXE_PATTERNS.search(context):
        return False
    for pattern in XXE_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.xxe",
                "category": "CWE-611",
                "title": "XML external entity (XXE) vulnerability",
                "description": f"XML parsing without entity restriction at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use defusedxml or disable external entity resolution",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "611"))
            return True
    return False


def _check_csrf(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-352 cross-site request forgery."""
    # Check surrounding context for CSRF protection
    context_start = max(0, line_num - 6)
    context_end = min(len(lines), line_num + 6)
    context = "\n".join(lines[context_start:context_end])
    if SAFE_CSRF_PATTERNS.search(context):
        return
    for pattern in CSRF_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "high",
                "check_id": "cwe.input_validation.missing_csrf",
                "category": "CWE-352",
                "title": "Missing CSRF protection",
                "description": f"State-changing endpoint without CSRF token at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Add CSRF token validation (CSRFProtect, csurf, or framework middleware)",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "352"))
            return


def _check_deserialization(
    file_path: Path, line: str, line_num: int, lines: list[str],
    findings: list[dict],
) -> None:
    """Check for CWE-502 deserialization of untrusted data."""
    if SAFE_DESERIALIZE_PATTERNS.search(line):
        return
    for pattern in DESERIALIZATION_PATTERNS:
        if pattern.search(line):
            finding = {
                "severity": "critical",
                "check_id": "cwe.input_validation.unsafe_deserialization",
                "category": "CWE-502",
                "title": "Deserialization of untrusted data",
                "description": f"Unsafe deserialization at line {line_num}",
                "file_path": str(file_path),
                "line_start": line_num,
                "line_end": line_num,
                "recommendation": "Use safe loaders (yaml.safe_load), avoid pickle with untrusted data, validate before deserializing",
            }
            finding["code_snippet"] = extract_snippet(lines, line_num)
            findings.append(enrich_finding(finding, "502"))
            return


check_input_validation_tool = function_tool(check_input_validation)
