def render(code):
    return f"\{eval(code)}"  # EXPECT: finding
