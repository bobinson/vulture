# ruff: noqa
def run_phase(result, runner):
    try:
        runner.go()
    except Exception as exc:
        result["degraded_reason"] = f"phase unavailable ({type(exc).__name__}: {str(exc)[:180]})"  # EXPECT: clean gap-K15-stored-reason
    store.save(result)
