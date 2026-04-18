"""Tests for CWE-331 / CWE-332 weak-entropy detection skill."""


def test_fires_on_python_random_flowing_to_token(tmp_path):
    """Python random.random() flowing into `token` fires CWE-331/CWE-332."""
    f = tmp_path / "v.py"
    f.write_text("import random\ntoken = random.random()\n")
    from cwe_agent.skills.weak_entropy_check import check_weak_entropy
    cwes = {x["category"] for x in check_weak_entropy(str(tmp_path))["findings"]}
    assert cwes & {"CWE-331", "CWE-332"}


def test_fires_on_js_math_random_flowing_to_key(tmp_path):
    """JS Math.random() flowing into `key` fires CWE-331/CWE-332."""
    f = tmp_path / "v.js"
    f.write_text("const key = Math.random();\n")
    from cwe_agent.skills.weak_entropy_check import check_weak_entropy
    cwes = {x["category"] for x in check_weak_entropy(str(tmp_path))["findings"]}
    assert cwes & {"CWE-331", "CWE-332"}


def test_no_fire_when_key_is_sort_kwarg(tmp_path):
    """random.random used as sort `key=` kwarg (non-crypto) must NOT fire."""
    f = tmp_path / "v.py"
    f.write_text("import random\nitems = []\nitems.sort(key=random.random)\n")
    from cwe_agent.skills.weak_entropy_check import check_weak_entropy
    assert check_weak_entropy(str(tmp_path))["findings"] == []


def test_no_fire_when_secrets_cooccur(tmp_path):
    """Co-occurrence with `secrets.token_hex` suppresses the finding."""
    f = tmp_path / "v.py"
    f.write_text(
        "import secrets, random\n"
        "token = random.random()\n"
        "secret = secrets.token_hex()\n"
    )
    from cwe_agent.skills.weak_entropy_check import check_weak_entropy
    assert check_weak_entropy(str(tmp_path))["findings"] == []


def test_no_fire_when_variable_name_contains_test(tmp_path):
    """Variable name containing `test` signals non-production usage; no finding."""
    f = tmp_path / "v.py"
    f.write_text("import random\ntest_random_value = random.random()\n")
    from cwe_agent.skills.weak_entropy_check import check_weak_entropy
    assert check_weak_entropy(str(tmp_path))["findings"] == []
