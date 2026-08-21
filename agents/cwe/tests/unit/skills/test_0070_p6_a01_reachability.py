"""Feature 0070 P6 — A01 reachability: CWE-1275 and CWE-219.

RED-phase tests. Written before the detectors exist, and deliberately including
the cases a naive implementation gets wrong.

Two entries, and they are NOT symmetric in how far they can be trusted:

1. **CWE-1275** (Sensitive Cookie with Improper SameSite Attribute) is a
   single-file, per-line predicate, so it is corpus-gateable and targets a
   VERIFIED band.

   The trap: CWE-1004/CWE-614 are "attribute absent ⇒ report" checks. SameSite is
   NOT. `sameSite: 'none'` is *present and vulnerable* — a predicate copied from
   its siblings passes on the worst case. Hence
   `test_samesite_none_is_reported`, which is the single most important test here.

2. **CWE-219** (Storage of File with Sensitive Data Under Web Root) is structural:
   it correlates a mount declaration in server code with the contents of a
   directory. `corpus_runner.run_deterministic()` copies each fixture to a temp
   dir as ONE flattened file renamed `_neutral.<ext>`, destroying both the
   directory layout and the filename, so CWE-219 **cannot be corpus-gated** by
   the current runner. It is unit-tested here and lands in DECLARED-ONLY. See the
   P6 section of the LLD for why extending the runner is deliberately not in
   scope.

CWE-219 must also stay disjoint from the EXISTING CWE-552 detector
(`_check_backup_exposure`), which already reports backup copies under a served
root at high severity. Disjointness is by `is_backup_name()`, asserted by
`test_backup_file_stays_552_not_219`.
"""

import tempfile
from pathlib import Path

import pytest

from cwe_agent.skills.info_exposure_check import check_information_exposure
from cwe_agent.skills.web_security_check import check_web_security


def _run(files: dict[str, str], skill) -> list[dict]:
    """Materialise `files` (path -> body) in a temp root and run one skill."""
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return skill(str(root))["findings"]


def _of(findings: list[dict], cwe: str) -> list[dict]:
    return [f for f in findings if f.get("category") == cwe]


# ---------------------------------------------------------------------------
# 1. CWE-1275 — SameSite
# ---------------------------------------------------------------------------


class TestCwe1275SameSite:
    def test_cookie_with_no_options_is_reported(self):
        """The commonest real shape: no options object at all."""
        f = _run({"a.ts": "res.cookie('token', updatedToken)\n"}, check_web_security)
        assert _of(f, "CWE-1275"), "a cookie with no SameSite must be reported"

    def test_samesite_none_is_reported(self):
        """THE asymmetry. `none` is present-and-vulnerable, not safe.

        A predicate copied from CWE-1004/614 ("attribute absent ⇒ report") passes
        here, which is the worst possible failure: SameSite=None is precisely the
        cross-site-sendable cookie CWE-1275 describes.
        """
        f = _run(
            {"a.ts": "res.cookie('token', t, { sameSite: 'none' })\n"},
            check_web_security,
        )
        assert _of(f, "CWE-1275"), "sameSite:'none' must be reported, not treated as safe"

    def test_samesite_none_case_insensitive(self):
        f = _run(
            {"a.ts": "res.cookie('token', t, { sameSite: 'None' })\n"},
            check_web_security,
        )
        assert _of(f, "CWE-1275"), "sameSite:'None' must be reported"

    @pytest.mark.parametrize("value", ["strict", "Strict", "lax", "Lax"])
    def test_samesite_strict_or_lax_is_safe(self, value):
        f = _run(
            {"a.ts": f"res.cookie('token', t, {{ sameSite: '{value}' }})\n"},
            check_web_security,
        )
        assert not _of(f, "CWE-1275"), f"sameSite:'{value}' is safe and must not be reported"

    def test_samesite_on_a_later_line_is_safe(self):
        """Multi-line options: the call-block window must reach the attribute.

        This is the CWE-1004 lesson — a fixed +/-3 window missed an attribute on
        the 6th line and produced false positives.
        """
        f = _run(
            {
                "a.ts": (
                    "res.cookie('token', t, {\n"
                    "  httpOnly: true,\n"
                    "  secure: true,\n"
                    "  path: '/',\n"
                    "  domain: 'example.com',\n"
                    "  maxAge: 3600,\n"
                    "  sameSite: 'strict',\n"
                    "})\n"
                )
            },
            check_web_security,
        )
        assert not _of(f, "CWE-1275"), "sameSite on a later line of the same call is safe"

    def test_python_set_cookie_samesite_is_safe(self):
        f = _run(
            {"a.py": "response.set_cookie('t', v, samesite='Strict')\n"},
            check_web_security,
        )
        assert not _of(f, "CWE-1275")

    def test_python_set_cookie_without_samesite_is_reported(self):
        f = _run({"a.py": "response.set_cookie('t', v)\n"}, check_web_security)
        assert _of(f, "CWE-1275")

    def test_non_cookie_line_is_not_reported(self):
        """A clean twin must be silent, not merely lower-severity."""
        f = _run(
            {"a.ts": "res.json({ sameSite: 'none' })\nconst x = 1\n"},
            check_web_security,
        )
        assert not _of(f, "CWE-1275"), "only cookie-setting calls are in scope"

    def test_one_row_per_unguarded_cookie_call(self):
        """Exactly one row per offending call site, and none for guarded ones."""
        f = _run(
            {
                "a.ts": "res.cookie('token', t)\n",
                "b.ts": "res.cookie('sid', v, { sameSite: 'none' })\n",
                "c.ts": "res.cookie('ok', v, { sameSite: 'strict' })\n",
            },
            check_web_security,
        )
        rows = _of(f, "CWE-1275")
        assert {Path(r["file_path"]).name for r in rows} == {"a.ts", "b.ts"}
        assert len(rows) == 2, f"expected one row per offending call, got {len(rows)}"


# ---------------------------------------------------------------------------
# 2. CWE-219 — sensitive non-backup file under a served root
# ---------------------------------------------------------------------------

_FTP_MOUNT = "app.use('/ftp', serveIndex('ftp', { icons: true }))\n"


class TestCwe219ServedSensitiveFiles:
    def test_sensitive_file_under_declared_mount_is_reported(self):
        f = _run(
            {"server.ts": _FTP_MOUNT, "ftp/credentials.kdbx": "KeePass\n"},
            check_information_exposure,
        )
        assert _of(f, "CWE-219"), "a KeePass DB under a served root must be reported"

    def test_mount_not_in_the_hardcoded_name_list_is_still_found(self):
        """Ground truth comes from the code, not from a guessed directory name.

        `vaultfiles` is NOT in `_SERVED_DIRS`, but the source declares the
        mount. A name-only implementation misses this and is why the resolver
        must parse mounts.
        """
        f = _run(
            {
                "server.ts": "app.use('/vaultfiles', serveIndex('vaultfiles'))\n",
                "vaultfiles/service-account.key": "-----BEGIN PRIVATE KEY-----\n",
            },
            check_information_exposure,
        )
        assert _of(f, "CWE-219"), "a mount declared in code must be honoured"

    def test_express_static_mount_is_honoured(self):
        f = _run(
            {
                "server.ts": "app.use('/d', express.static('served'))\n",
                "served/db.sql": "INSERT INTO users\n",
            },
            check_information_exposure,
        )
        assert _of(f, "CWE-219")

    def test_sensitive_file_not_under_any_served_root_is_clean(self):
        """Clean twin: same file, no mount reaching it."""
        f = _run(
            {"server.ts": "app.listen(3000)\n", "secrets/incident.kdbx": "KeePass\n"},
            check_information_exposure,
        )
        assert not _of(f, "CWE-219"), "an unserved directory is not a web-root exposure"

    def test_served_root_with_only_harmless_files_is_clean(self):
        """Clean twin: a served root holding only publishable content."""
        f = _run(
            {
                "server.ts": "app.use('/.well-known', express.static('.well-known'))\n",
                ".well-known/security.txt": "Contact: mailto:x@y.z\n",
            },
            check_information_exposure,
        )
        assert not _of(f, "CWE-219")

    def test_empty_served_root_is_clean(self):
        """Clean twin: a mount whose directory is created at runtime."""
        f = _run(
            {"server.ts": "app.use('/support/logs', serveIndex('logs'))\n"},
            check_information_exposure,
        )
        assert not _of(f, "CWE-219")

    def test_backup_file_stays_552_not_219(self):
        """Disjointness with the EXISTING detector, by `is_backup_name()`.

        `_check_backup_exposure` already reports backup copies under a served
        root. CWE-219 must not double-report them.
        """
        f = _run(
            {"server.ts": _FTP_MOUNT, "ftp/package.json.bak": '{"name":"x"}\n'},
            check_information_exposure,
        )
        assert _of(f, "CWE-552"), "the existing backup detector must keep firing"
        assert not _of(f, "CWE-219"), "a backup copy is CWE-552's row, not CWE-219's"

    def test_reports_exactly_the_sensitive_files_and_nothing_else(self):
        """One row per sensitive served file; backups and harmless files excluded.

        An exact-set assertion, not a membership check — see
        `test_armored_pgp_is_not_reported` for why that distinction caught a real
        false-positive class.
        """
        f = _run(
            {
                "server.ts": _FTP_MOUNT,
                "ftp/vault.kdbx": "KeePass\n",
                "ftp/compiled.pyc": "\x00bytecode\n",
                "ftp/readme.md": "# hello\n",
                "ftp/config.json.bak": "{}\n",
            },
            check_information_exposure,
        )
        names = {Path(r["file_path"]).name for r in _of(f, "CWE-219")}
        assert names == {"vault.kdbx", "compiled.pyc"}, (
            f"expected only the sensitive non-backup files, got {sorted(names)}"
        )

    def test_armored_pgp_is_not_reported(self):
        """`.asc`/`.gpg` under a served root are publishable by design.

        The first cut of `_SENSITIVE_SERVED_SUFFIXES` included them, which flags
        every advisory feed that publishes detached signatures at a well-known
        path (CSAF/OpenVEX do exactly this). Armored signatures and public keys
        carry no exposure signal; private key material is covered by
        `.key`/`.pem`/`.p12`/`.pfx`/`.ppk`.
        """
        f = _run(
            {
                "server.ts": "app.use('/.well-known', express.static('.well-known'))\n",
                ".well-known/csaf/advisory.json": "{}\n",
                ".well-known/csaf/advisory.json.asc": "-----BEGIN PGP SIGNATURE-----\n",
                ".well-known/pubkey.gpg": "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            },
            check_information_exposure,
        )
        assert not _of(f, "CWE-219"), "published signatures are not an exposure"

    def test_private_key_under_served_root_is_still_reported(self):
        """The complement of the above: armored PRIVATE material must not slip."""
        f = _run(
            {
                "server.ts": "app.use('/k', express.static('keys'))\n",
                "keys/server.pem": "-----BEGIN RSA PRIVATE KEY-----\n",
            },
            check_information_exposure,
        )
        assert _of(f, "CWE-219")


class TestSharedServedRootResolver:
    """DRY: one resolver, consumed by both CWE-552 and CWE-219."""

    def test_resolver_unions_code_mounts_with_fallback_names(self):
        from cwe_agent.skills.info_exposure_check import served_roots

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "server.ts").write_text(
                "app.use('/e', serveIndex('vaultfiles'))\n"
            )
            roots = served_roots(str(root))
        assert "vaultfiles" in roots, "a code-declared mount must be resolved"
        assert "public" in roots, "the fallback name list must still apply"

    def test_552_escalates_for_a_code_declared_mount(self):
        """The shared resolver benefits the EXISTING detector too.

        A backup under a mount that is absent from `_SERVED_DIRS` was previously
        scored `medium`; deriving the mount from code makes it `high`.
        """
        f = _run(
            {
                "server.ts": "app.use('/x', express.static('customdir'))\n",
                "customdir/config.json.bak": "{}\n",
            },
            check_information_exposure,
        )
        rows = _of(f, "CWE-552")
        assert rows, "the backup must still be reported"
        assert rows[0]["severity"] == "high", (
            "a backup under a code-declared mount is served, so it must escalate"
        )


class TestDryCookieSpecTable:
    """The three cookie attribute checks must be one routine + three specs.

    Guards the DRY requirement structurally: `_check_cookie_httponly` and
    `_check_cookie_secure` were already near-identical, and a third hand-written
    copy for SameSite is what this pins against.
    """

    def test_one_spec_per_attribute(self):
        from cwe_agent.skills.web_security_check import COOKIE_ATTRIBUTE_SPECS

        cwes = {s.cwe for s in COOKIE_ATTRIBUTE_SPECS}
        assert cwes == {"1004", "614", "1275"}, (
            "all three cookie attribute checks must be table-driven, not copied"
        )

    def test_spec_categories_are_source_literals(self):
        """The attestation finds emitted CWEs by SCANNING SOURCE for the literal
        ``"category": "CWE-N"``, so a table-driven refactor that builds the
        category with an f-string silently drops those CWEs from
        ``VERIFIED_CWES.md`` while detection keeps working.

        That regression happened during this phase: collapsing the three cookie
        checks made CWE-614 and CWE-1004 vanish from the report (A02 reachable
        4 -> 2). Pinned here because the failure is invisible at runtime — every
        detection test still passes.
        """
        import re as _re
        from pathlib import Path as _Path

        from cwe_agent.skills import web_security_check
        from cwe_agent.skills.web_security_check import COOKIE_ATTRIBUTE_SPECS

        # Same regex the coverage reporter uses (report_coverage._CATEGORY_LITERAL_RE).
        literal_re = _re.compile(r'"category"\s*:\s*"CWE-(\d+)"')
        source = _Path(web_security_check.__file__).read_text()
        discoverable = set(literal_re.findall(source))

        for spec in COOKIE_ATTRIBUTE_SPECS:
            assert spec.cwe in discoverable, (
                f"CWE-{spec.cwe} is emitted but not discoverable as a source "
                'literal "category": "CWE-N" — the coverage attestation will '
                "under-report it"
            )
