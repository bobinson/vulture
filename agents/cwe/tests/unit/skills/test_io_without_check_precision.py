"""CWE-754 must fire on real I/O, not on any call named open/send/connect.

IO_WITHOUT_CHECK was a single bare pattern:

    (?:open|read|write|connect|send|recv)\\s*\\([^)]*\\)\\s*$

matching the *verb alone*, with no regard for the receiver. In one measured sweep
it produced 81 findings — every one carrying the same title, and 76 of them
were not I/O at all:

    this.snackBarHelperService.open(...)      Angular Material snackbar
    res.send(...)                            Express response
    socket.disconnect()                       ends with 'connect()'
    dialog.open(...)                          Angular dialog

Those 81 rows were the *sole* carrier of OWASP category A10, so A10's "found"
status rested entirely on false positives. A category is better reported
not-found than propped up by noise.

The fix keys on the receiver: filesystem/network/OS namespaces, Go file
handles, and Python builtins — not any identifier that happens to expose a
similarly-named method.
"""

import tempfile
from pathlib import Path

from cwe_agent.skills.error_handling_check import check_error_handling


def _run(files: dict[str, str]) -> list[dict]:
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        for name, body in files.items():
            p = root / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(body)
        return check_error_handling(str(root))["findings"]


def _io(findings):
    return [f for f in findings
            if f.get("check_id") == "cwe.error_handling.io_no_check"]


class TestNoFalsePositivesOnNonIO:
    def test_angular_snackbar_open_is_not_io(self):
        body = (
            "export class Component {\n"
            "  notify (msg: string) {\n"
            "    this.snackBarHelperService.open(msg)\n"
            "  }\n"
            "}\n"
        )
        assert not _io(_run({"a.ts": body})), \
            "snackBarHelperService.open() is a UI call, not I/O"

    def test_express_res_send_is_not_io(self):
        body = (
            "function handler (req, res) {\n"
            "  res.send({ status: 'ok' })\n"
            "}\n"
        )
        assert not _io(_run({"r.js": body})), "res.send() is an HTTP response, not raw I/O"

    def test_disconnect_is_not_connect(self):
        body = "function teardown (socket) {\n  socket.disconnect()\n}\n"
        assert not _io(_run({"s.ts": body})), \
            "'disconnect()' must not match the 'connect' verb"

    def test_dialog_open_is_not_io(self):
        body = "openDialog () {\n  this.dialog.open(SomeComponent)\n}\n"
        assert not _io(_run({"d.ts": body})), "dialog.open() is a UI call"

    def test_shapes_produce_nothing(self):
        """All four observed shapes together must yield zero CWE-754 rows."""
        body = (
            "this.snackBarHelperService.open('saved')\n"
            "res.send(result)\n"
            "socket.disconnect()\n"
            "this.dialog.open(Cmp)\n"
        )
        assert not _io(_run({"all.ts": body})), "none of the observed UI shapes is I/O"


class TestStillDetectsRealIO:
    def test_python_builtin_open_unchecked(self):
        body = "def load(path):\n    data = open(path).read()\n    return data\n"
        assert _io(_run({"m.py": body})), "an unchecked builtin open() must still be reported"

    def test_python_os_write_unchecked(self):
        body = "import os\ndef dump(fd, buf):\n    os.write(fd, buf)\n"
        assert _io(_run({"w.py": body})), "os.write() without error handling must be reported"

    def test_node_fs_write_unchecked(self):
        body = "const fs = require('fs')\nfunction save (p, d) {\n  fs.writeFileSync(p, d)\n}\n"
        assert _io(_run({"n.js": body})), "fs.writeFileSync() without a guard must be reported"

    def test_socket_send_unchecked(self):
        body = "import socket\ndef ping(sock):\n    sock.send(b'hi')\n"
        assert _io(_run({"p.py": body})), "socket send() without error handling must be reported"

    def test_guarded_io_is_not_reported(self):
        body = (
            "def load(path):\n"
            "    try:\n"
            "        return open(path).read()\n"
            "    except OSError:\n"
            "        return None\n"
        )
        assert not _io(_run({"g.py": body})), "guarded I/O must not be reported"
