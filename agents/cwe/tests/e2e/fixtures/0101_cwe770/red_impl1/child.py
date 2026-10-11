import subprocess


def spawn_and_collect(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out = []
    for line in proc.stdout:
        # EXPECT-NEXT: finding child stdout iterated after a Popen in the same routine (keyword stdout= is not a binding)
        out.append(line)
    return out


def child_given(cmd, proc):
    out = []
    for line in proc.stdout:
        # EXPECT-NEXT: finding child stdout of a process handed in
        out.append(line)
    return out


def relay(session, url, stream):
    session.get(url, stream=True)
    parts = []
    for part in stream:
        # EXPECT-NEXT: finding a stream parameter iterated (the keyword stream=True binds nothing)
        parts.append(part)
    return parts


def keyword_named_like_a_source(rows, build):
    out = []
    for row in build(rows, stdout=None):
        # EXPECT-NEXT: clean iteration over a helper's result; the keyword stdout= binds nothing
        out.append(row)
    return out
