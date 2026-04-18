import pytest


@pytest.mark.parametrize("literal,expected_cwe", [
    ('"foo.txt."',        "42"),   # trailing dot
    ('"foo.txt...."',     "43"),   # multiple trailing dots
    ('"foo.txt "',        "46"),   # trailing whitespace
    ('"foo bar.txt"',     "48"),   # internal whitespace
    ('"foo.txt/"',        "49"),   # trailing slash
    ('"//etc/passwd"',    "50"),   # multiple leading slashes
    ('"/etc//passwd"',    "51"),   # multiple internal slashes
    ('"/etc/passwd//"',   "52"),   # multiple trailing slashes
    ('"foo\\\\"',         "54"),   # trailing backslash
    ('"/./foo"',          "55"),   # single-dot directory
    ('"foo*.txt"',        "56"),   # wildcard
    ('"fake/../real/f"',  "57"),   # directory traversal equivalence
])
def test_path_equivalence_variants_in_open_call(tmp_path, literal, expected_cwe):
    """Each variant fires when the literal is inside a path-using call."""
    f = tmp_path / "v.py"
    f.write_text(f"open({literal})\n")  # open( is a path-call gate
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    result = check_path_equivalence(str(tmp_path))
    cwes = {fnd["category"] for fnd in result["findings"]}
    assert f"CWE-{expected_cwe}" in cwes, f"CWE-{expected_cwe} not in {cwes}"


def test_no_firing_on_log_sentence(tmp_path):
    """Log message ending in '.' must NOT fire CWE-42."""
    f = tmp_path / "v.py"
    f.write_text('logger.info("Operation completed.")\n')
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    assert check_path_equivalence(str(tmp_path))["findings"] == []


def test_no_firing_on_version_string(tmp_path):
    """Dotted version assignment must NOT fire."""
    f = tmp_path / "v.py"
    f.write_text('VERSION = "1.2.3"\n')
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    assert check_path_equivalence(str(tmp_path))["findings"] == []


def test_no_firing_on_regex_pattern(tmp_path):
    """Regex with * or ? must NOT fire CWE-56."""
    f = tmp_path / "v.py"
    f.write_text('pattern = re.compile(r"\\d+\\.\\d+")\n')
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    assert check_path_equivalence(str(tmp_path))["findings"] == []


def test_no_firing_on_http_url(tmp_path):
    """URL in requests.get() (not a path call) must NOT fire CWE-50/51."""
    f = tmp_path / "v.py"
    f.write_text('requests.get("https://example.com/api/v1/x")\n')
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    assert check_path_equivalence(str(tmp_path))["findings"] == []


def test_fires_on_os_path_join_with_traversal(tmp_path):
    """Classical ../ inside os.path.join fires CWE-57."""
    f = tmp_path / "v.py"
    f.write_text('os.path.join(base, "fake/../real/f")\n')
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    cwes = {x["category"] for x in check_path_equivalence(str(tmp_path))["findings"]}
    assert "CWE-57" in cwes


def test_fires_on_path_constructor(tmp_path):
    """pathlib.Path(literal) is a path-call gate."""
    f = tmp_path / "v.py"
    f.write_text('p = pathlib.Path("../secret")\n')
    from cwe_agent.skills.path_equivalence_check import check_path_equivalence
    cwes = {x["category"] for x in check_path_equivalence(str(tmp_path))["findings"]}
    assert "CWE-57" in cwes
