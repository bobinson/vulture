# ruff: noqa
def main():
    try:
        run()
    except Exception as e:
        # EXPECT-NEXT: clean  py stderr cli
        sys.stderr.write(f'error: {e}\n')
        sys.exit(1)
