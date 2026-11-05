# ruff: noqa -- a CWE-778 fixture read as text: undefined names and unused bindings are its subject.
import enum, os
# R7 optional best-effort cleanup
def cleanup(tmp):
    try:
        os.remove(tmp)
    except FileNotFoundError:  # EXPECT: finding known-gap (residual, still reported): R7 optional remove
        pass
