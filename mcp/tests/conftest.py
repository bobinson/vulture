import os
import pytest

@pytest.fixture(autouse=True)
def vulture_env(monkeypatch):
    """Set minimal env for all tests."""
    monkeypatch.setenv("VULTURE_URL", "http://localhost:28080")
    monkeypatch.setenv("VULTURE_MCP_ALLOW_WRITE", "false")

@pytest.fixture(autouse=True)
def reset_client():
    """Reset the global client between tests to prevent cross-test leaks."""
    yield
    try:
        import server
        if hasattr(server, '_client'):
            server._client = None
    except ImportError:
        pass
