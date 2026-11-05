"""A command line entry point. `_` is an ordinary Python name, not a Go
blank identifier, and Python reports failure by raising."""
import argparse


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--verbose", action="store_true")
    # EXPECT-NEXT: clean
    _ = parser.parse_args(argv)
    # EXPECT-NEXT: clean
    _, _ = divmod(len(argv), 2)
    return 0
