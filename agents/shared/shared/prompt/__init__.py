"""Unified prompt library — feature 0089.

Public API. Nothing in production imports this until Phase 2.
"""

from .fragment import Fragment, Role, Stance
from .lint import LintAllow, LintFinding, LintReport, gate, lint
from .profile import ModelProfile, Structured, ToolSchema, profile_for
from .render import Mode, RenderedPrompt, render
from .slots import Slot
from .spec import PromptSpec

__all__ = [
    "Fragment", "LintAllow", "LintFinding", "LintReport", "Mode",
    "ModelProfile", "PromptSpec", "RenderedPrompt", "Role", "Slot", "Stance",
    "Structured", "ToolSchema", "gate", "lint", "profile_for", "render",
]
