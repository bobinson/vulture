"""Re-export of ``shared.testing.isolation`` so the e2e import path is unchanged.

The implementation moved to ``shared.testing.isolation`` so agent suites other
than this one can apply the same isolation; ``tests.support.isolation`` is the
path the e2e business-logic tests import, so it stays as this alias. No logic
lives here.
"""

from __future__ import annotations

from shared.testing.isolation import isolate

__all__ = ["isolate"]
