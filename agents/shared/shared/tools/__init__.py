"""Shared tools for audit agents."""

from shared.tools.file_reader import read_file, read_file_tool
from shared.tools.file_lister import list_files, list_files_tool
from shared.tools.pattern_matcher import search_pattern, search_pattern_tool
from shared.tools.ast_parser import parse_ast, parse_ast_tool
from shared.tools.dependency_checker import check_dependencies, check_dependencies_tool
from shared.tools.git_history import git_log, git_log_tool

ALL_TOOLS = [
    read_file_tool,
    list_files_tool,
    search_pattern_tool,
    parse_ast_tool,
    check_dependencies_tool,
    git_log_tool,
]

__all__ = [
    "read_file", "read_file_tool",
    "list_files", "list_files_tool",
    "search_pattern", "search_pattern_tool",
    "parse_ast", "parse_ast_tool",
    "check_dependencies", "check_dependencies_tool",
    "git_log", "git_log_tool",
    "ALL_TOOLS",
]
