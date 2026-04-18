"""Tests for CWE-778 insufficient-logging detection skill."""


def test_fires_on_python_bare_pass_except(tmp_path):
    """Python except block with bare pass and no log fires CWE-778."""
    f = tmp_path / "v.py"
    f.write_text(
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging
    cwes = {x["category"] for x in check_insufficient_logging(str(tmp_path))["findings"]}
    assert "CWE-778" in cwes


def test_fires_on_java_empty_catch(tmp_path):
    """Java empty catch block fires CWE-778."""
    f = tmp_path / "V.java"
    f.write_text(
        "public class V {\n"
        "    public void run() {\n"
        "        try { foo(); } catch (Exception e) {}\n"
        "    }\n"
        "}\n"
    )
    from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging
    cwes = {x["category"] for x in check_insufficient_logging(str(tmp_path))["findings"]}
    assert "CWE-778" in cwes


def test_no_fire_when_logger_error_in_body(tmp_path):
    """except block with logger.error must NOT fire."""
    f = tmp_path / "v.py"
    f.write_text(
        "import logging\n"
        "logger = logging.getLogger(__name__)\n"
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError as e:\n"
        "        logger.error(e)\n"
    )
    from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging
    assert check_insufficient_logging(str(tmp_path))["findings"] == []


def test_no_fire_with_logging_exception(tmp_path):
    """except block with logging.exception must NOT fire."""
    f = tmp_path / "v.py"
    f.write_text(
        "import logging\n"
        "def run(x):\n"
        "    try:\n"
        "        x()\n"
        "    except ValueError:\n"
        '        logging.exception("failed")\n'
    )
    from cwe_agent.skills.insufficient_logging_check import check_insufficient_logging
    assert check_insufficient_logging(str(tmp_path))["findings"] == []
