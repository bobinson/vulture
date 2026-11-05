TEMPLATE = "${eval(y)}"  # EXPECT: clean
ESCAPED = f"{{eval(y)}}"  # noqa: F541 -- read as text. EXPECT: clean
