def persist_preferences(theme):
    open("/etc/app/state.txt", "w").write(f"theme={theme}")
