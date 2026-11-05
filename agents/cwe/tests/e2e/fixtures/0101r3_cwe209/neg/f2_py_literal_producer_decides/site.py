# ruff: noqa
class Check:
    def __init__(self, ok, error=None):
        self.ok = ok
        self.error = error


def check_form(form):
    if not form.get("name"):
        return Check(False, "name is required")
    return Check(True)


def submit(request, response):
    job = Job()
    try:
        persist(request.form)
    except Exception as exc:
        job.error = exc
        jobs.save(job)
    c = check_form(request.form)
    if not c.ok:
        return response.json({"error": c.error})  # EXPECT: clean literal-producer-decides
