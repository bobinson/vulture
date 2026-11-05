"""A small proxy in front of the scanner.

The host check answers 400 to a request naming another host, which
EXPECT-NEXT: clean
refuses a rebinding page with a forbidden status before any route runs;
the app serves nothing else on the port.
"""

import os


def port():
    return int(os.environ.get("PORT", "8080"))
