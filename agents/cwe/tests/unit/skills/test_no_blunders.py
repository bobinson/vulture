"""Lock-in tests pinning the dual contract for tightened detectors:
known false positives stay suppressed, known true positives still fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cwe_agent.skills.input_validation_check import (
    PATH_TRAVERSAL_PATTERNS,
    FILE_UPLOAD_STRONG,
    _check_file_upload,
)
from cwe_agent.skills.injection_check import CODE_INJECTION_PATTERNS
from cwe_agent.skills.crypto_check import _check_hardcoded_key, _check_broken_crypto
from cwe_agent.skills.auth_check import _check_hardcoded_creds
from cwe_agent.skills.info_exposure_check import _check_cleartext_storage


def _matches_any(patterns, line: str) -> bool:
    return any(p.search(line) for p in patterns)


class TestCWE22Positives:
    @pytest.mark.parametrize("line", [
        # Web-framework input
        'path = os.path.join(base, request.body)',
        'open(req.params["file"]).read()',
        'Path(request.args.get("file"))',
        'fs.readFile(req.body.path, cb)',
        'res.sendFile(req.params.filename)',
        # Variable suffixes (\w* relaxation)
        'open(user_input)',
        'os.path.join(base, request_path)',
        'fs.readFile(req_data.file, cb)',
        # File-naming convention
        'open(filename)',
        'open(filepath)',
        'open(fname)',
        'open(file_path)',
        'open(filePath)',
        'open(uploaded_file)',
        'open(uploaded_filename)',
        'open(user_filename)',
        'os.path.join(BASE, filename)',
        'Path(file_path)',
        'fs.readFile(filename, cb)',
        'res.sendFile(filepath)',
        # CLI input
        'open(argv[1])',
        'os.path.join(base, args.file)',
        # Payload (deserialized)
        'open(payload["file"])',
        # Go: r.URL.Query().Get(...) form
        'data, err := ioutil.ReadFile(c.URL.Query().Get("file"))',
        'f, err := os.Open(r.FormValue("path"))',
        # Java
        'Files.readString(Paths.get(request.getParameter("path")))',
    ])
    def test_must_fire(self, line: str) -> None:
        assert _matches_any(PATH_TRAVERSAL_PATTERNS, line), (
            f"CWE-22 should fire on: {line!r}"
        )


class TestCWE22Negatives:
    @pytest.mark.parametrize("line", [
        # Scoped npm package names
        '  "@chromatic-com/storybook",',
        '  "@storybook/addon-a11y",',
        # TypeScript relative imports
        'import { resolveAddressToIds } from "../resolvers/resolveAddressToIds";',
        'import { mapData } from "../usa/federal/mapper";',
        # URL string literals
        'const URL = "https://geocoding.geo.census.gov/geocoder/path";',
        'const API = "https://api.example.com/v1/endpoint";',
        # Storybook config
        'addons: ["@chromatic-com/storybook"],',
        # Go module imports
        'import "github.com/example/package"',
        # `..` in a string literal that isn't a fs call
        'const note = "see ../README.md for details";',
        # Plain math/logic with /
        'const ratio = a / b;',
    ])
    def test_must_not_fire(self, line: str) -> None:
        assert not _matches_any(PATH_TRAVERSAL_PATTERNS, line), (
            f"CWE-22 must not flag (was FP): {line!r}"
        )


class TestCWE434Positives:
    @pytest.mark.parametrize("line", [
        # Python frameworks
        'file = request.files["upload"]',
        'parser_classes = (MultiPartParser,)',
        # Node.js libraries
        'const upload = multer({ dest: "/uploads" });',
        'app.use(formidable({ multiples: true }));',
        'busboy({ headers: req.headers })',
        'router.post("/avatar", upload.single("file"), handler)',
        'router.post("/photos", upload.array("photos"), handler)',
        # Go
        'file, header, err := r.FormFile("upload")',
        'reader, err := r.MultipartReader()',
        # HTML / JSX
        '<input type="file" name="avatar" />',
        '<input  type =  "file"  />',
        '<Field type="file" name="document" />',
        '<Dropzone onDrop={onDrop}>',
        # FormData / browser File API
        'const fd = new FormData();',
        'formData.append("file", blob);',
        'formData.append("attachment", file)',
        'const file = event.target.files[0];',
        'const file = e.target.files[0];',
        'const dropped = event.dataTransfer.files[0];',
        # Hooks
        'const { getRootProps } = useDropzone({ onDrop });',
        # Rails
        'has_one_attached :avatar',
        'has_many_attached :photos',
        # Spring (Java)
        'public void upload(@RequestParam MultipartFile file)',
        # Multipart literal in code
        'headers: { "Content-Type": "multipart/form-data" }',
    ])
    def test_must_fire(self, line: str) -> None:
        assert _matches_any(FILE_UPLOAD_STRONG, line), (
            f"CWE-434 should fire on: {line!r}"
        )


class TestCWE434Negatives:
    """The full _check_file_upload skill (extension-aware) must NOT
    flag bare-identifier mentions in JSX, GraphQL actions, DB column
    listings, or .d.ts files — the FP class that produced 110 hits on
    togetherapp."""

    @pytest.mark.parametrize("filename, line", [
        ("AvatarInput.tsx", 'import { UploadIcon } from "ui";'),
        ("AvatarInput.tsx", 'const [isUploadingAvatar, setIsUploadingAvatar] = useState(false);'),
        ("AvatarInput.tsx", '  handleAvatarUploadComplete,'),
        ("actions.yaml", '  - name: finalizeAssetUpload'),
        ("actions.yaml", '  - name: prepareAssetUpload'),
        ("public_userAnimationFlags.yaml", '        - uploadProfilePictureAnimationSeen'),
        ("public_userAnimationFlags.yaml", '        - lastUploadProfilePictureAnimationDate'),
        ("api.d.ts", 'export interface UploadConfig { maxSize: number; }'),
    ])
    def test_must_not_fire(self, filename: str, line: str, tmp_path: Path) -> None:
        f = tmp_path / filename
        findings: list[dict] = []
        _check_file_upload(f, line, 1, (line,), findings)
        assert findings == [], (
            f"CWE-434 must not fire on {filename}:{line!r} (was FP)"
        )


class TestCWE94Positives:
    @pytest.mark.parametrize("line", [
        'eval(user_input)',
        'exec(user_input)',
        '  eval("dangerous")',
        ';eval(payload)',
        '}eval(payload)',
        ',eval(payload)',
        '(eval(payload))',
        'const f = new Function("return " + input);',
        # Qualified eval shapes
        'globalThis.eval(payload);',
        'window.eval(scriptText);',
        'self.eval(payload);',
        'global.eval(payload);',
        'globalThis.Function("return user_input")();',
        # setTimeout / setInterval with string
        'setTimeout("doSomething()", 100);',
        'setInterval("update()", 1000);',
    ])
    def test_must_fire(self, line: str) -> None:
        assert _matches_any(CODE_INJECTION_PATTERNS, line), (
            f"CWE-94 should fire on: {line!r}"
        )


class TestCWE94Negatives:
    @pytest.mark.parametrize("line", [
        # JavaScript regex matching
        'const m = /\\d+/.exec(s);',
        'const zip = /\\d{5}/.exec(input);',
        # Database method named exec
        'await db.exec("SELECT * FROM t");',
        'await connection.exec(sql);',
        # Method via array index
        'handlers[i].exec(args);',
        # Method on chained call
        'getRegex().exec(input);',
    ])
    def test_must_not_fire(self, line: str) -> None:
        assert not _matches_any(CODE_INJECTION_PATTERNS, line), (
            f"CWE-94 must not flag method call: {line!r}"
        )


class TestVarSuppressionContract:
    """Auth, info-exposure, and crypto detectors all share the
    var-reference suppression. Lock both sides of the contract:
    suppress var-refs, fire on real literal secrets."""

    @pytest.mark.parametrize("line", [
        '--build-arg STRIPE_SECRET_KEY="$STRIPE_SECRET_KEY"',
        'PGPASSWORD="${POSTGRES_PASSWORD}"',
        'api_key: \'%(SECRET_KEY)s\'',
        'token: {{ .Values.apiKey }}',
    ])
    def test_var_ref_no_finding(self, line: str) -> None:
        f1: list[dict] = []
        _check_hardcoded_creds(Path("/x.yml"), line, 1, (line,), line, f1, {})
        f2: list[dict] = []
        _check_cleartext_storage(Path("/x.yml"), line, 1, (line,), line, f2, {})
        f3: list[dict] = []
        _check_hardcoded_key(Path("/x.yml"), line, 1, (line,), f3)
        assert f1 == f2 == f3 == [], (
            f"All three detectors should suppress: {line!r}"
        )

    @pytest.mark.parametrize("line", [
        'api_key = "sk_live_realsecret1234567890abcdef"',
        'aes_key = "0123456789abcdef0123456789abcdef"',
    ])
    def test_literal_secret_still_fires(self, line: str) -> None:
        f1: list[dict] = []
        _check_hardcoded_creds(Path("/x.py"), line, 1, (line,), line, f1, {})
        f3: list[dict] = []
        _check_hardcoded_key(Path("/x.py"), line, 1, (line,), f3)
        assert (f1 or f3), f"At least one detector must fire on real secret: {line!r}"


class TestCWE327Positives:
    @pytest.mark.parametrize("line", [
        'from Crypto.Cipher import DES',
        'cipher = Cipher.getInstance("DES");',
        'mode = "ECB"',
        'cipher = DES.new(key, MODE_ECB)',
        'crypto.createCipher("RC4", key)',
    ])
    def test_must_fire(self, line: str) -> None:
        findings: list[dict] = []
        _check_broken_crypto(Path("/x.py"), line, 1, (line,), findings)
        assert findings, f"CWE-327 should fire on: {line!r}"


class TestCWE327Negatives:
    @pytest.mark.parametrize("line", [
        # Bare DES on a non-crypto line — no context keyword, must NOT fire
        'const DESCRIBE = "test"',
        'def test_DESC_ordering():',
        'state.aes_DES_compat = false;',
        'message = "running DESCRIBE statement"',
    ])
    def test_must_not_fire(self, line: str) -> None:
        findings: list[dict] = []
        _check_broken_crypto(Path("/x.py"), line, 1, (line,), findings)
        assert findings == [], f"CWE-327 must not flag bare DES substring: {line!r}"
