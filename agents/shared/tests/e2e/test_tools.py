"""E2E tests for shared tools. These define the business contract."""

import json
from pathlib import Path

import pytest

from shared.tools.file_reader import read_file
from shared.tools.file_lister import list_files
from shared.tools.pattern_matcher import search_pattern
from shared.tools.ast_parser import parse_ast
from shared.tools.dependency_checker import check_dependencies
from shared.tools.git_history import git_log


@pytest.fixture
def sample_project(tmp_path: Path) -> Path:
    """Create a sample project structure for testing."""
    # Python file
    py_file = tmp_path / "main.py"
    py_file.write_text(
        "import os\nimport sys\n\ndef hello(name: str) -> str:\n"
        '    return f"Hello, {name}"\n\nif __name__ == "__main__":\n'
        "    print(hello(sys.argv[1]))\n"
    )

    # Go file
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "fmt"\n\nfunc main() {\n'
        '    fmt.Println("hello")\n}\n'
    )

    # Subdirectory with files
    subdir = tmp_path / "pkg"
    subdir.mkdir()
    (subdir / "util.py").write_text("def add(a: int, b: int) -> int:\n    return a + b\n")
    (subdir / "__init__.py").write_text("")

    # Requirements file
    (tmp_path / "requirements.txt").write_text("fastapi>=0.115.0\nuvicorn>=0.32.0\npydantic>=2.10.0\n")

    # Package.json
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0", "lodash": "^4.17.21"}})
    )

    # Go mod
    (tmp_path / "go.mod").write_text(
        "module example.com/test\n\ngo 1.23\n\n"
        "require (\n\tgithub.com/gin-gonic/gin v1.9.1\n)\n"
    )

    return tmp_path


class TestFileReader:
    """Tests for the read_file tool."""

    def test_file_reader_reads_file(self, sample_project: Path) -> None:
        """read_file returns the full content of a file."""
        result = read_file(str(sample_project / "main.py"))
        assert "import os" in result
        assert "def hello" in result

    def test_file_reader_reads_line_range(self, sample_project: Path) -> None:
        """read_file with start/end returns only those lines."""
        result = read_file(str(sample_project / "main.py"), start_line=4, end_line=5)
        assert "def hello" in result
        assert "import os" not in result

    def test_file_reader_nonexistent_file(self) -> None:
        """read_file returns error message for missing files."""
        result = read_file("/nonexistent/path/file.txt")
        assert "error" in result.lower()

    def test_file_reader_empty_range(self, sample_project: Path) -> None:
        """read_file with start_line=0 and end_line=0 reads entire file."""
        result = read_file(str(sample_project / "main.py"), start_line=0, end_line=0)
        assert "import os" in result
        assert "def hello" in result


class TestFileLister:
    """Tests for the list_files tool."""

    def test_file_lister_lists_files(self, sample_project: Path) -> None:
        """list_files returns all files in a directory."""
        result = list_files(str(sample_project))
        assert any("main.py" in f for f in result)
        assert any("main.go" in f for f in result)

    def test_file_lister_with_pattern(self, sample_project: Path) -> None:
        """list_files with pattern filters results."""
        result = list_files(str(sample_project), pattern="*.py")
        assert any("main.py" in f for f in result)
        assert all(".go" not in f for f in result)

    def test_file_lister_recursive(self, sample_project: Path) -> None:
        """list_files finds files in subdirectories."""
        result = list_files(str(sample_project), pattern="*.py")
        assert any("util.py" in f for f in result)

    def test_file_lister_nonexistent_dir(self) -> None:
        """list_files returns empty list for missing directory."""
        result = list_files("/nonexistent/directory")
        assert result == []


class TestPatternMatcher:
    """Tests for the search_pattern tool."""

    def test_pattern_matcher_finds_patterns(self, sample_project: Path) -> None:
        """search_pattern finds regex matches across files."""
        result = search_pattern(str(sample_project), r"def \w+")
        assert len(result) > 0
        assert any(m["match"].startswith("def ") for m in result)

    def test_pattern_matcher_returns_file_and_line(self, sample_project: Path) -> None:
        """search_pattern results include file path and line number."""
        result = search_pattern(str(sample_project), r"import os")
        assert len(result) >= 1
        match = result[0]
        assert "file" in match
        assert "line" in match
        assert "match" in match
        assert match["line"] >= 1

    def test_pattern_matcher_no_matches(self, sample_project: Path) -> None:
        """search_pattern returns empty list when nothing matches."""
        result = search_pattern(str(sample_project), r"NONEXISTENT_PATTERN_XYZ")
        assert result == []


class TestAstParser:
    """Tests for the parse_ast tool."""

    def test_ast_parser_python(self, sample_project: Path) -> None:
        """parse_ast detects Python language and extracts structure."""
        result = parse_ast(str(sample_project / "main.py"))
        assert result["language"] == "python"
        assert "functions" in result
        assert any(f["name"] == "hello" for f in result["functions"])

    def test_ast_parser_unsupported_file(self, sample_project: Path) -> None:
        """parse_ast returns language unknown for unsupported files."""
        txt_file = sample_project / "readme.txt"
        txt_file.write_text("just text")
        result = parse_ast(str(txt_file))
        assert result["language"] == "unknown"


class TestDependencyChecker:
    """Tests for the check_dependencies tool."""

    def test_check_dependencies_requirements_txt(self, sample_project: Path) -> None:
        """check_dependencies reads requirements.txt."""
        result = check_dependencies(str(sample_project))
        assert "dependencies" in result
        deps = result["dependencies"]
        assert any(d["name"] == "fastapi" for d in deps)

    def test_check_dependencies_package_json(self, sample_project: Path) -> None:
        """check_dependencies reads package.json."""
        result = check_dependencies(str(sample_project))
        deps = result["dependencies"]
        assert any(d["name"] == "express" for d in deps)

    def test_check_dependencies_go_mod(self, sample_project: Path) -> None:
        """check_dependencies reads go.mod."""
        result = check_dependencies(str(sample_project))
        deps = result["dependencies"]
        assert any("gin" in d["name"] for d in deps)

    def test_check_dependencies_empty_dir(self, tmp_path: Path) -> None:
        """check_dependencies returns empty deps for dir with no manifests."""
        result = check_dependencies(str(tmp_path))
        assert result["dependencies"] == []


class TestGitLog:
    """Tests for the git_log tool."""

    def test_git_log_non_repo(self, tmp_path: Path) -> None:
        """git_log returns empty list for non-git directory."""
        result = git_log(str(tmp_path))
        assert result == []
