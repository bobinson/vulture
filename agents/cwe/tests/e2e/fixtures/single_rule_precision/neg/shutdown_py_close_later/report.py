"""Write rows as comma-separated text."""


def write_report(path, rows):
    # EXPECT-NEXT: clean
    handle = open(path, "w", encoding="utf-8")
    header = ",".join(rows[0].keys())
    handle.write(header + "\n")
    for row in rows:
        values = [str(v) for v in row.values()]
        handle.write(",".join(values) + "\n")
    handle.flush()
    handle.close()
    return path
