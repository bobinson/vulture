"""RED team: redaction tests. These must FAIL until server.py implements redact_secrets."""
import pytest


def test_redacts_password_in_snippet():
    from server import redact_secrets
    result = redact_secrets('db_password = "hunter2"')
    assert "hunter2" not in result
    assert "***" in result


def test_redacts_bearer_token():
    from server import redact_secrets
    result = redact_secrets("Authorization: Bearer ghp_abc123xyz456def789ghi")
    assert "ghp_abc123xyz456def789ghi" not in result


def test_redacts_postgres_dsn():
    from server import redact_secrets
    result = redact_secrets("postgres://admin:s3cret@db.neon.tech/vulture")
    assert "s3cret" not in result
    assert "postgres://***@" in result


def test_redacts_mongodb_dsn():
    from server import redact_secrets
    result = redact_secrets("mongodb+srv://user:pass123@cluster.mongodb.net/db")
    assert "pass123" not in result


def test_redacts_vulture_api_key():
    from server import redact_secrets
    result = redact_secrets("key=vk_abcdefghij1234567890")
    assert "vk_abcdefghij" not in result


def test_redacts_aws_key():
    from server import redact_secrets
    result = redact_secrets("aws_key=AKIAIOSFODNN7EXAMPLE1")
    assert "AKIAIOSFODNN7EXAMPLE1" not in result


def test_preserves_non_secret_content():
    from server import redact_secrets
    safe = "def process(data):\n    return data.upper()\n"
    assert redact_secrets(safe) == safe


def test_redacts_multiple_patterns():
    from server import redact_secrets
    text = 'token="sk-proj-abc123def456ghi789" and password="hunter2"'
    result = redact_secrets(text)
    assert "sk-proj-abc123def456ghi789" not in result
    assert "hunter2" not in result


def test_none_and_empty_input():
    from server import redact_secrets
    assert redact_secrets(None) == ""
    assert redact_secrets("") == ""
