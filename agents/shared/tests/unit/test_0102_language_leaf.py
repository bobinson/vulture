"""Feature 0102, task 0.3: ``detect_language`` lives in the leaf ``shared.language``.

The AST layer (``shared.ast``) keys its language profiles by the names
``detect_language`` returns, so it must import the detector. The detector used
to live in ``shared.validate.language``, and importing anything under
``shared.validate`` runs ``shared/validate/__init__.py``, which pulls in the
judge, the voter and the rest of the validation phase. A parse layer that
dragged those in would break its own leaf discipline.

So the body lives in ``shared/language.py`` and every caller imports it from
there. These tests pin the two halves of that contract:

* the leaf is importable under its public name;
* importing the leaf in a fresh interpreter does not load ``shared.validate``.

What the detector answers is pinned by ``validate/test_language.py``.
"""

from __future__ import annotations

from tests.support.fresh_import import loaded_after_import


def test_detect_language_imports_from_the_leaf() -> None:
    """The public name resolves to a callable."""
    from shared.language import detect_language

    assert callable(detect_language)


def test_leaf_import_does_not_load_shared_validate() -> None:
    """A fresh ``import shared.language`` leaves ``shared.validate`` unloaded."""
    loaded = loaded_after_import("shared.language", ("shared.validate",))

    assert loaded == [], (
        "importing shared.language pulled shared.validate into sys.modules; "
        "the leaf must not import the validation phase"
    )
