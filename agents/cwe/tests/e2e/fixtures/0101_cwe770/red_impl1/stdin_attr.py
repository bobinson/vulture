import fileinput
import sys


def binary_stdin_lines():
    out = []
    for line in sys.stdin.buffer:
        # EXPECT-NEXT: finding stdin through an attribute chain (the receiver chain carries the role)
        out.append(line)
    return out


def all_input_lines():
    out = []
    for line in fileinput.input():
        # EXPECT-NEXT: finding lines of every input file or stdin
        out.append(line)
    return out


def config_rows(settings):
    out = []
    for row in settings.defaults.rows:
        # EXPECT-NEXT: clean an attribute chain with no source role
        out.append(row)
    return out
