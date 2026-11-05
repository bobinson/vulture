def leading_newline(cur, x):
    cur.execute("\nSELECT * FROM t WHERE id = {}".format(x))  # EXPECT: finding


def method_chain(cur, x):
    cur.execute("SELECT * FROM t WHERE id = {}".strip().format(x))  # EXPECT: finding


def spaced(cur, x):
    cur.execute("SELECT * FROM t WHERE id = '{}'" .format(x))  # EXPECT: finding


def after_other_format(cur, arrow, n):
    cur.execute("SELECT * FROM t WHERE d = '" + arrow.now().format('YYYY') + "' AND n = '{}'".format(n))  # EXPECT: finding
