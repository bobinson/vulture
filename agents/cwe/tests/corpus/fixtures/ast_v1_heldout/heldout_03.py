# held-out heldout_03 (CWE-78): a web framework's admin entry point dispatching on the process argv
# HELD-OUT-TOKENS: execute_from_command_line
import os
import sys


def main():
    os.environ.setdefault("APP_SETTINGS_MODULE", "lab_site.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError("the web framework is not installed") from exc
    execute_from_command_line(sys.argv)


if __name__ == "__main__":
    main()
