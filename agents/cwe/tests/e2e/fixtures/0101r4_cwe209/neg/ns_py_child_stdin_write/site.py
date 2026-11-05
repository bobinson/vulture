# ruff: noqa
def relay(proc):
    try:
        run()
    except Exception as exc:
        proc.stdin.write(str(exc).encode())  # EXPECT: clean ns-py-child-stdin
