"""Unit tests for normalise_source_path in src/translate.py.

Covers TM4 (argv injection) and BLOCKER #9 (path traversal / symlink
escape). RED phase (feature 0053).
"""

import os


# RED-phase import — will fail until GREEN ships src/translate.py.
from src.translate import normalise_source_path  # noqa: E402


def test_accepts_valid_subpath_of_root(tmp_path):
    root = str(tmp_path)
    sub = tmp_path / "src-1"
    sub.mkdir()
    result = normalise_source_path(str(sub), root=root)
    # realpath may differ on macOS (/private/var/...). Check that the
    # returned path resolves to the same on-disk dir.
    assert result is not None
    assert os.path.realpath(result) == os.path.realpath(str(sub))


def test_accepts_root_exactly(tmp_path):
    root = str(tmp_path)
    result = normalise_source_path(root, root=root)
    assert result is not None
    assert os.path.realpath(result) == os.path.realpath(root)


def test_rejects_flag_style_BLOCKER9(tmp_path):
    # TM4: a source_path starting with `-` would be interpreted as a flag
    # by Semgrep's argv. Wrapper must reject before the subprocess call.
    assert normalise_source_path("-rm-rf", root=str(tmp_path)) is None
    assert normalise_source_path("--config", root=str(tmp_path)) is None


def test_rejects_dot_dot_traversal_BLOCKER9(tmp_path):
    # `..` anywhere in the path components is rejected without even
    # calling realpath — defence in depth.
    assert normalise_source_path(str(tmp_path / ".." / "etc" / "passwd"), root=str(tmp_path)) is None
    assert normalise_source_path("../etc/passwd", root=str(tmp_path)) is None


def test_rejects_empty(tmp_path):
    assert normalise_source_path("", root=str(tmp_path)) is None
    assert normalise_source_path(None, root=str(tmp_path)) is None


def test_rejects_non_string(tmp_path):
    assert normalise_source_path(123, root=str(tmp_path)) is None
    assert normalise_source_path(["/audit-inputs"], root=str(tmp_path)) is None
    assert normalise_source_path({"path": "/audit-inputs"}, root=str(tmp_path)) is None


def test_rejects_outside_root(tmp_path):
    other = tmp_path.parent  # one level above the root
    assert normalise_source_path(str(other), root=str(tmp_path)) is None
    assert normalise_source_path("/etc/passwd", root=str(tmp_path)) is None


def test_rejects_symlink_escape(tmp_path):
    """BLOCKER #9: a symlink inside the root pointing outside must be
    rejected. The wrapper uses os.path.realpath which resolves symlinks,
    and the prefix check then fails because the resolved target is
    outside the root."""
    root = tmp_path / "audit-inputs"
    root.mkdir()
    outside = tmp_path / "secrets"
    outside.mkdir()
    (outside / "passwd").write_text("root:x:0:0::/root:/bin/bash\n")

    evil_link = root / "evil"
    os.symlink(str(outside), str(evil_link))

    # The symlink itself is inside `root`, but its real target is not.
    # normalise_source_path must reject this — otherwise Semgrep would
    # follow the symlink and scan files outside the audit mount.
    assert normalise_source_path(str(evil_link), root=str(root)) is None


def test_rejects_path_that_only_prefixes_root_textually(tmp_path):
    # A pure string-prefix check (no separator) would accept
    # "/audit-inputs-evil" against root "/audit-inputs". The
    # implementation must require either equality or a trailing
    # separator after the root.
    root = tmp_path / "audit-inputs"
    root.mkdir()
    sibling = tmp_path / "audit-inputs-evil"
    sibling.mkdir()
    assert normalise_source_path(str(sibling), root=str(root)) is None
