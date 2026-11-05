"""The e2e suite runs under the unit suite's isolation: the same fixture,
imported rather than copied, so there is one implementation
(``tests/unit/conftest.py`` -> ``tests.support.isolation.isolate``)."""

from tests.unit.conftest import _isolate_vulture_env  # noqa: F401  (autouse fixture)
