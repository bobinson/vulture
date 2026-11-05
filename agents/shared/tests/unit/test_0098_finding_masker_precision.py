"""Unit contract: the finding-text masker is precise (feature 0098, items 4 and 18).

``mask_secret_values`` runs over the ``code_snippet`` and ``description`` of
every finding from every agent. It must mask what is a credential by its shape,
and leave alone what only looks long and hex-ish: prose after "Bearer"/"Basic",
git SHAs, image digests, hashes, UUIDs and CSS class names. It must never join
two lines, must mask a private-key BODY (not just its header) without touching
the code next to the delimiters, and must stay linear on long input.

``redact_for_log`` keeps its breadth: anything the old log pattern masked is
still masked there. Key and token fixtures are built by concatenation so no
literal in this file looks like a live credential.
"""

from __future__ import annotations

import base64
import re
import time

import pytest

from shared.llm.errors import mask_secret_values, redact_for_log

P = "X"
BEGIN = "-----" + "BEGIN"
END = "-----" + "END"
KEY_ROW = "MIIEowIBAAKCAQEA" + "xyz0123456789abcdef"
KEY_ROW2 = "Zm9vYmFyYmF6cXV4" + "MTIzNDU2Nzg5MA=="
HEX32 = "0123456789abcdef" * 2
MD5 = "d41d8cd98f00b204e9800998ecf8427e"
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
CHECKOUT_SHA = "b4ffde65f46336ab88eb53be808477a3936bae11"


def _mask(text: str) -> str:
    return mask_secret_values(text, P)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


PROSE = {
    "Basic camel acronym": "is a Basic HTTPAuthenticationScheme",
    "Bearer camel acronym": "Bearer AuthenticationSchemeHandlerForAPIs",
    "reviewer prose": "The API accepts Bearer authentication for every call; "
                      "this is a basic misconfiguration.",
    "Basic camel": "Basic AuthenticationRequiredHeader is set",
    "Basic authenticationRequired": "Basic authenticationRequired header",
    "Bearer tokenAuthentication": "uses Bearer tokenAuthentication middleware",
    "Bearer camel 24+": "uses Bearer tokenAuthenticationMiddleware here",
    "Basic auth/authz prose": "Basic authentication/authorization is enabled by default.",
    "Bearer path prose": "Uses Bearer authentication/OAuth2 tokens for every route.",
}

NOT_CREDENTIALS = {
    "checkout sha": "uses: actions/checkout@" + CHECKOUT_SHA,
    "image digest": "image: nginx@sha256:" + "a" * 8 + "0123456789abcdef" * 3 + "01234567",
    "md5 constant": f"MD5_EMPTY = '{MD5}'",
    "uuid lower": "id = 550e8400e29b41d4a716446655440000",
    "uuid upper": "ID 550E8400E29B41D4A716446655440000",
    "css class": '<div class="sk-folding-cube-container">',
    "css class long": '<div class="sk-folding-cube-container-inner-wrapper">',
    "css class digit": '<div class="sk-spinner-rotating-plane2">',
    "kwarg password": "conn = connect(host=h, password=db_password)",
    "cache_key": f'3: cache_key = "{MD5}"',
    "author_commit": f'3: author_commit = "{SHA1}"',
    "integrity_key": f'3: "integrity_key": "{MD5}"',
    "primaryKey": f'primaryKey = "{MD5}"',
    "monkey": f'monkey = "{MD5}"',
    "digest compare": f'if digest == "{MD5}":',
    "password hash": f'password_hash: "{MD5}"',
    "public java constant": f'public static final String COMMIT_SHA = "{SHA1}";',
    "lockfile sha": f'3: "resolved": "git+https://github.com/o/r.git#{SHA1}"',
}


@pytest.mark.parametrize("text", list(PROSE.values()), ids=list(PROSE))
def test_prose_after_bearer_or_basic_is_not_masked(text: str) -> None:
    assert _mask(text) == text


@pytest.mark.parametrize("text", list(NOT_CREDENTIALS.values()), ids=list(NOT_CREDENTIALS))
def test_identifiers_that_are_not_credentials_are_not_masked(text: str) -> None:
    assert _mask(text) == text


@pytest.mark.parametrize("text", [
    "headers = 'Bearer\nsomething_long_identifier = 1'",
    "x = 'Basic\nconfigurationOptionsX'",
    "auth = 'Bearer'\n" + "a1b2c3d4e5f6g7h8i9j0k1l2 = 1",
])
def test_masking_never_joins_two_lines(text: str) -> None:
    assert _mask(text) == text


KEY_WINDOWS = {
    "numbered window": f"1: KEY = '''{BEGIN} RSA PRIVATE KEY-----\n2: {KEY_ROW}\n"
                       f"3: {END} RSA PRIVATE KEY-----'''",
    "window below BEGIN": f"2: {KEY_ROW}\n3: {KEY_ROW2}\n4: {END} RSA PRIVATE KEY-----'''\n"
                          "5: os.system(x)",
    "one-line json": f'"key": "{BEGIN} PRIVATE KEY-----\\n{KEY_ROW}\\n{KEY_ROW2}\\n'
                     f'{END} PRIVATE KEY-----\\n"',
    "js concatenation": f'1: const k = "{BEGIN} PRIVATE KEY-----\\n" +\n2:   "{KEY_ROW}\\n" +\n'
                        f'3:   "{END} PRIVATE KEY-----";',
    "pgp block": f"1: {BEGIN} PGP PRIVATE KEY BLOCK-----\n2: lQOYBF{'Q' * 58}\n"
                 f"3: {END} PGP PRIVATE KEY BLOCK-----",
    "crlf text": f"{BEGIN} PRIVATE KEY-----\r\n{KEY_ROW}\r\n{KEY_ROW2}\r\n"
                 f"{END} PRIVATE KEY-----",
}


@pytest.mark.parametrize("text", list(KEY_WINDOWS.values()), ids=list(KEY_WINDOWS))
def test_a_private_key_body_is_masked_in_any_window(text: str) -> None:
    out = _mask(text)

    assert KEY_ROW not in out and KEY_ROW2 not in out and "QQQQQQQQ" not in out
    assert out.count("\n") == text.count("\n")


@pytest.mark.parametrize("text", [
    "10: def serializePrivateKeyToPem(self, privateKeyMaterial):\n"
    f"11:     return body + '{END} PRIVATE KEY-----'",
    f"10: HEADER = '{BEGIN} PRIVATE KEY-----'\n"
    "11: def loadPrivateKeyFromEnvironment(configurationLoader):\n"
    "12:     return configurationLoader.readEnvironmentVariable()",
    f"A private key ({BEGIN} RSA PRIVATE KEY-----) is committed; rotate it with "
    "keyManagementService/AWSSecretsManager.",
])
def test_code_next_to_a_key_delimiter_is_not_masked(text: str) -> None:
    """Only the delimiter itself may be masked; the code around it is evidence."""
    expected = text.replace(f"{BEGIN} RSA PRIVATE KEY-----", P).replace(
        f"{BEGIN} PRIVATE KEY-----", P)

    assert _mask(text) == expected


SECRETS = {
    "basic admin:admin": "Authorization: Basic " + _b64(b"admin:admin"),
    "basic user:pass12": "Authorization: Basic " + _b64(b"user:pass12"),
    "BASIC upper": "AUTHORIZATION: BASIC " + _b64(b"user:pass12"),
    "go :=": f'3: apiKey := "{HEX32}"',
    "php =>": f"3: 'secret' => '{HEX32}',",
    "py annotated": f'3: SECRET_KEY: str = "{HEX32}"',
    "aes_key": f'aes_key = "{HEX32}"',
    "secret_key": 'secret_key = "f3a9c1d2e3f4a5b6c7d8e9f0a1b2c3d4"',
    "yaml client_secret": "client_secret: " + HEX32.upper(),
    "HTTPS userinfo": "HTTPS://deploy:" + "Pw4ndR0ckz99zz@host/x",
    "git+https userinfo": "git+https://u:" + "pw@host/x.git",
    "extra-index-url": "--extra-index-url https://u:" + "pw@pypi.example/simple",
    "bearer letters": "Authorization: Bearer abcdEfghIjklMnopQrstUvwxyzABCDEF",
    "BEARER upper": "Authorization: BEARER a1b2c3d4e5f6g7h8i9j0k1l2",
    "bearer jwt": "Bearer " + "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxIn0.sig12345",
    "sk- no digit": "OPENAI_API_KEY=sk-" + "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
    "sk-proj": "sk-" + "proj-abcDEF0123456789012345",
    "sk-ABC": "sk-" + "ABCDEF1234567890",
    "anthropic": "sk-" + "ant-api03-" + "A" * 40 + "1",
    "ghp": "ghp_" + "a1" * 18,
    "AKIA": "AKIA" + "IOSFODNN7EXAMPLE",
    "xoxb": "xoxb-" + "1234567890-abcdef",
    "AIza short": "AIza" + "SyA1234567890",
    "jwt without a dot": "eyJ" + "hbGciOiJIUzI1NiJ9abcd",
    # A token right after Bearer in a header value (reviewer R3).
    "bearer header letters": "Authorization: Bearer " + "abcdefghijklmnopqrstuvwxyz" + "ABCD",
    "bearer header 20 mixed": "Authorization: Bearer " + "AbCdEfGhIjKlMnOpQrSt",
    "bearer quoted letters": '{"Authorization": "Bearer ' + "abcdefghijklmnopqrstuvwxyz" + 'ABCD"}',
    "bearer quoted digit 12": 'h = "Bearer ' + "a1b2c3d4e5f6" + '"',
    # Provider-prefixed tokens (reviewer R5).
    "stripe live": "sk_" + "live_" + "a1B2" * 6,
    "stripe restricted": "rk_" + "test_" + "a1B2" * 6,
    "github fine-grained": "github_" + "pat_" + "11ABCDEFG0" * 5,
    "npm": "npm_" + "a1B2c3D4e5" * 3 + "F6g7H8",
    "gitlab": "glpat-" + "a1B2c3D4e5F6g7H8i9J0",
    "sendgrid": "SG." + "a1B2c3D4e5F6g7H8i9" + "." + "J0k1L2m3N4o5P6q7R8",
    "huggingface": "hf_" + "abcdefghijklmnopqrstuvwxyzABCDEF",
    "slack webhook": "https://hooks.slack.com/services/" + "T0000AAAA/B0000BBBB/" + "XyZ1" * 6,
    "azure account key": "DefaultEndpointsProtocol=https;AccountName=a;AccountKey="
                         + "a1B2+c3D4/e5F6==" + ";EndpointSuffix=core.windows.net",
    "connection string password": '"Server=db;Database=app;User Id=sa;Password='
                                  + "S3cretPassw0rdXYZ" + ';"',
    "redis empty user": "redis://:" + "S3cretPassw0rdXYZ" + "@cache:6379/0",
    "aws secret access key": 'aws_secret_access_key = "' + "wJalrXUtnFEMI/K7MDENG/"
                             + "bPxRfiCYEXAMPLEKEY" + '"',
}

# A 32+ hex value on a line that names a credential, wherever the credential
# word sits in the name and whatever the separator (reviewer R1 / R16).
KEYED_HEX = {
    "rails secret_key_base yaml": "secret_key_base: {h}",
    "rails secret_key_base env": "SECRET_KEY_BASE={h}",
    "rails config": 'config.secret_key_base = "{h}"',
    "flask config subscript": 'app.config["SECRET_KEY"] = "{h}"',
    "environ subscript": 'os.environ["SECRET_KEY"] = "{h}"',
    "dict subscript": 'cfg["api_key"] = "{h}"',
    "header subscript": 'headers["X-Api-Key"] = "{h}"',
    "single quote subscript": "headers['X-Api-Key'] = '{h}'",
    "php define": 'define("SECRET_KEY", "{h}");',
    "dotnet appsettings": '<add key="ApiKey" value="{h}" />',
    "go typed var": 'var apiKey string = "{h}"',
    "getenv default": 'SECRET_KEY = os.getenv("SECRET_KEY", "{h}")',
    "fromhex": 'encryption_key = bytes.fromhex("{h}")',
    "auth": 'auth = "{h}"',
    "dockerfile env": "ENV API_KEY {h}",
    "cli flag": "--api-key {h}",
    "make": "API_KEY ?= {h}",
    "r assign": 'api_key <- "{h}"',
    "cmake": 'set(API_KEY "{h}")',
    "bare apikey": "apikey {h}",
    "suffix prod": "API_KEY_PROD = '{h}'",
    "suffix version": "api_key_v2 = '{h}'",
    "middle word": "client_secret_value = '{h}'",
    "backtick": "const KEY = `{h}`",
    "java constant": 'public static final String API_KEY = "{h}";',
}


@pytest.mark.parametrize("text", list(KEYED_HEX.values()), ids=list(KEYED_HEX))
def test_hex_on_a_credential_named_line_is_masked(text: str) -> None:
    for h in (HEX32, HEX32.upper(), HEX32 * 2):
        out = _mask(text.format(h=h))

        assert h not in out
        assert P in out


@pytest.mark.parametrize("text", list(SECRETS.values()), ids=list(SECRETS))
def test_high_confidence_shapes_are_still_masked(text: str) -> None:
    out = _mask(text)

    assert out != text
    assert P in out


@pytest.mark.parametrize("text", [
    *SECRETS.values(),
    "uses: actions/checkout@" + CHECKOUT_SHA,
    f"MD5_EMPTY = '{MD5}'",
    "OPENAI_API_KEY=sk-" + "test-no-network-key",
    "auth header was Bearer authentication_token_x",
])
def test_log_redaction_keeps_its_breadth(text: str) -> None:
    """Logs are one sanitised line where over-masking costs nothing: everything
    the old log pattern masked, including bare hex and loose sk-/Bearer, still is."""
    assert redact_for_log(text) != " ".join(text.split())


@pytest.mark.parametrize("text", [
    "ab-" * 34_000,
    "key" * 34_000,
    "ab." * 34_000,
    "x_key" * 20_000 + "=",
    "var a_key=b.c;" * 7_200,
    "Bearer " + "a" * 100_000,
    ("1: " + "A" * 64 + "\n") * 1_500,
    f"{BEGIN} PRIVATE KEY-----" + "ab-" * 30_000,
    "sk-" * 34_000,
    ("1: " + "A" * 40 + "\n") * 2_000 + f"{END} PRIVATE KEY-----",
    "api_key " + (HEX32 + " ") * 3_000,
    "a://" * 25_000,
    "x" + "a:" * 50_000,
    ";Password=" * 10_000,
    '"Bearer ' * 12_000,
    "Authorization: Bearer " + "Ab" * 50_000,
    "sk-" + "ab-" * 33_000,
    "hooks.slack.com/services/" * 4_000,
    "AbCd" * 25_000,
    "SG." + "a" * 50_000 + ".",
    "aws_secret_access_key=" + "A" * 100_000,
    "npm_" * 25_000,
    "hf_" + "a" * 100_000 + "1",
    ";AccountKey=" + "a" * 100_000,
    "Bearer " + "AuthenticationScheme" * 5_000,
    "x" * 99_000 + " " + HEX32 * 30,
], ids=["ab-", "key", "ab.", "x_key", "minified", "bearer", "numbered-b64", "begin-ab-", "sk-",
        "rows-above-end", "keyed-hex", "schemes", "colons", "conn-string", "quoted-bearer",
        "bearer-mixed", "sk-segments", "slack", "camel", "sendgrid", "aws", "npm", "hf",
        "account-key", "camel-words", "long-line-hex"])
def test_masking_is_linear_on_long_lines(text: str) -> None:
    """ReDoS guard: 100k characters in well under a second (about 0.05 s measured;
    the old masker took 14-20 s on the ``ab-`` run)."""
    start = time.monotonic()
    mask_secret_values(text, P)
    redact_for_log(text)

    assert time.monotonic() - start < 0.5


# The log pattern as it stood before feature 0098 refined it: every span it
# masked must still be masked by ``redact_for_log`` (reviewer R4).
_HEAD_SECRETISH = re.compile(
    r"(?i)("
    r"[a-z][a-z0-9+.\-]*://[^\s/@:]+:[^\s/@]+@"
    r"|\bAIza[0-9A-Za-z_\-]{10,}"
    r"|\bsk-[0-9A-Za-z_\-]{12,}"
    r"|\beyJ[0-9A-Za-z._\-]{16,}"
    r"|\bgh[pousr]_[0-9A-Za-z]{16,}"
    r"|\bxox[baprse]-[0-9A-Za-z\-]{10,}"
    r"|\b(?:AKIA|ASIA|AROA|AIDA|ANPA|AIPA)[0-9A-Z]{12,}"
    r"|\bBearer\s+[0-9A-Za-z._\-]{12,}"
    r"|\bBasic\s+[0-9A-Za-z+/=]{16,}"
    r"|-----BEGIN[ A-Z]{0,40}PRIVATE KEY-----"
    r"|\b[0-9a-f]{32,}\b"
    r")"
)

LOG_CORPUS = [
    *SECRETS.values(),
    *PROSE.values(),
    *NOT_CREDENTIALS.values(),
    *(t.format(h=HEX32) for t in KEYED_HEX.values()),
    "conn my_postgres://admin:" + "S3cretPassw0rd@db",
    "postgres://admin:" + "p" * 300 + "@db",
    "postgres://" + "u" * 300 + ":pw@db",
    "9postgres://admin:" + "pw@db",
    "Bearer AuthenticationSchemeHandlerForAPIs",
    "class sk-spinner-rotating-plane2",
    "OPENAI_API_KEY=sk-" + "test-no-network-key",
]


@pytest.mark.parametrize("text", LOG_CORPUS)
def test_log_redaction_masks_everything_the_old_log_pattern_masked(text: str) -> None:
    line = " ".join(text.split())
    out = redact_for_log(text)

    for m in _HEAD_SECRETISH.finditer(line):
        assert m.group(0) not in out
