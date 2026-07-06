"""Regression guard (feature 0058): --project-root is VERSION-CONDITIONAL.

`--project-root` pins the scan root so Semgrep's default `.semgrepignore`
(e.g. `tests/`) doesn't silently skip audited files. But the pinned image
Semgrep (1.84.0) has no such flag and errors on it — which once made EVERY
audit return 0 findings. So the wrapper probes support and only emits the
flag where the installed Semgrep accepts it; the pinned baseline (probe
False) must never carry the flag.
"""

import src.wrapper as wrapper
from src.wrapper import _semgrep_argv


def _pairs(argv):
    return list(zip(argv, argv[1:]))


def test_project_root_omitted_when_unsupported(monkeypatch):
    monkeypatch.setattr(wrapper, "_project_root_supported", lambda: False)
    argv = _semgrep_argv("/audit-inputs/abc123", {})
    assert "--project-root" not in argv


def test_project_root_included_when_supported(monkeypatch):
    monkeypatch.setattr(wrapper, "_project_root_supported", lambda: True)
    argv = _semgrep_argv("/audit-inputs/abc123", {})
    assert ("--project-root", "/audit-inputs/abc123") in _pairs(argv)


def test_semgrep_argv_terminates_options_before_target(monkeypatch):
    # The target must follow a `--` terminator and be the final arg,
    # regardless of the --project-root decision.
    for supported in (True, False):
        monkeypatch.setattr(wrapper, "_project_root_supported", lambda: supported)
        argv = _semgrep_argv("/audit-inputs/abc123", {})
        assert argv[-2:] == ["--", "/audit-inputs/abc123"]


def test_project_root_probe_defaults_false_on_error(monkeypatch):
    # A probe that blows up must fail safe to the pinned baseline (off).
    wrapper._project_root_supported.cache_clear()

    def boom(*a, **k):
        raise OSError("semgrep missing")

    monkeypatch.setattr(wrapper.subprocess, "run", boom)
    assert wrapper._project_root_supported() is False
    wrapper._project_root_supported.cache_clear()
