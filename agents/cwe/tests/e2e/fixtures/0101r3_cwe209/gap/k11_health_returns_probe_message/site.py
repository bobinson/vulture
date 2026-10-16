# ruff: noqa
def build_app(probe):
    app = make_app()

    @app.get("/health")
    def health():
        status = probe.check()
        return {"status": "ok", "llm_ready": status.ok, "llm_message": status.message()}  # EXPECT: clean gap-K11-return-style-crossfile

    return app
