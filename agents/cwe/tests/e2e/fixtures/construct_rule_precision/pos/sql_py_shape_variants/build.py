def split_select(cols, t):
    return (f"SELECT {cols} "  # EXPECT: finding
            f"FROM {t} WHERE x = 1")


def insert_or_replace(v):
    return "INSERT OR REPLACE INTO kv VALUES ('%s')" % v  # EXPECT: finding


def update_alias(v):
    return "UPDATE users u SET name = '%s'" % v  # EXPECT: finding


def long_select(uid):
    return "SELECT col_0, col_1, col_2, col_3, col_4, col_5, col_6, col_7, col_8, col_9, col_10, col_11, col_12, col_13, col_14, col_15, col_16, col_17, col_18, col_19, col_20, col_21, col_22, col_23, col_24, col_25, col_26, col_27, col_28, col_29 FROM users WHERE id = '%s'" % uid  # EXPECT: finding


def escaped_newline(x):
    return f"\nSELECT * FROM t WHERE id = {x}"  # EXPECT: finding


def escaped_tab(t):
    return "SELECT *\tFROM %s" % t  # EXPECT: finding
