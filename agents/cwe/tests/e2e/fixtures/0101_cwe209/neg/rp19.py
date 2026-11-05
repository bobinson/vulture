# ruff: noqa
try:
    run()
except Exception as e:
    # EXPECT-NEXT: clean
    sys.stderr.write(str(e))
