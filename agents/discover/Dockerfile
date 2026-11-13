FROM vulture-agent-base:latest
# Playwright's bundled Node driver links libatomic.so.1 since 1.65, and
# python:3.12-slim does not ship it. The driver runs `install --with-deps`
# itself, so the library must already be present: --with-deps cannot supply it.
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/*
COPY discover/ /app/discover/
RUN pip install --no-cache-dir "/app/discover[playwright]"
RUN playwright install --with-deps chromium
EXPOSE 28008
CMD ["sh", "-c", "uvicorn discover_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28008}"]
