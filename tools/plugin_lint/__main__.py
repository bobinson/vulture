"""Module entry point — allows `python -m plugin_lint <path>`."""
from plugin_lint.lint import main

if __name__ == "__main__":
    raise SystemExit(main())
