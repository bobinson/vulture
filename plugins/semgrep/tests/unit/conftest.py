"""Unit-scope fixtures for the semgrep plugin.

The unit tests drive the app in-process as a plugin started by hand, which has
no agent token. A ``VULTURE_AGENT_TOKEN`` inherited from a developer shell or a
CI job would make every ``/run`` in them answer 403, so it is removed for each
unit test. The E2E tests set or clear it themselves.
"""

import pytest


@pytest.fixture(autouse=True)
def _no_agent_token(monkeypatch):
    monkeypatch.delenv("VULTURE_AGENT_TOKEN", raising=False)
