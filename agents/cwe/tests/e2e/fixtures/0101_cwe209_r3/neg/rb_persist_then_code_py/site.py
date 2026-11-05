# ruff: noqa
def run_job(ident):
    try:
        work(ident)
        return Outcome(True)
    except Exception as exc:
        db.execute("UPDATE jobs SET error = %s WHERE id = %s", (str(exc), ident))
        Job.objects.filter(id=ident).update(error=str(exc))
        return Outcome(False, error="JOB_FAILED")


def show(handler, ident):
    outcome = run_job(ident)
    handler.wfile.write(outcome.error.encode())  # EXPECT: clean clean-persisted-py
