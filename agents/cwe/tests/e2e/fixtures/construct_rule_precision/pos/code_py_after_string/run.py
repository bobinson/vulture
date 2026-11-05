def run(code):
    label = "it's"; eval(code)  # noqa: E702 -- read as text. EXPECT: finding
    return label
