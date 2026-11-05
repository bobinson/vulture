# ruff: noqa
def run_plugins(plugins, ctx):
    failed = []
    for plugin in plugins:
        try:
            plugin.run(ctx)
        except Exception as exc:
            failed.append(f"{plugin.name} ({exc})")  # EXPECT: clean gap-K18-collected-then-returned
    return failed
