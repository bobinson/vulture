# ruff: noqa
def write_report(path, results):
    with open(path, 'w') as fh:
        for r in results:
            if r.exc:
                # EXPECT-NEXT: clean  py file report
                fh.write(f'{r.name}: {r.exc}\n')
