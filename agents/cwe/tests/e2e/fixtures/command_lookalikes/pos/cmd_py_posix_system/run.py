import posix


def f(c):
    posix.system(c)  # EXPECT: finding
