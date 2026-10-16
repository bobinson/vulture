# ruff: noqa -- a CWE-778 fixture read as text: undefined names and unused bindings are its subject.
import sys
def main():
    try:
        run()
    except RuntimeError as e:  # EXPECT: finding known-gap (residual, still reported): R8b CLI print to stderr + exit
        print(f"migration error: {e}", file=sys.stderr)
        sys.exit(1)
