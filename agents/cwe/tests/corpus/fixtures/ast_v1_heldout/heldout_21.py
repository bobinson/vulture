# held-out heldout_21 (CWE-78): a project's admin script handing the process argv to the web framework's dispatcher
# HELD-OUT-TOKENS: execute_from_command_line
"""Administrative entry point."""
import os
import sys


def main():
    os.environ.setdefault("APP_SETTINGS_MODULE", "site_core.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("the web framework is not installed") from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
