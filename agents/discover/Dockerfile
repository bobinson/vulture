FROM vulture-agent-base:latest
COPY discover/ /app/discover/
RUN pip install --no-cache-dir "/app/discover[playwright]"
RUN playwright install --with-deps chromium
EXPOSE 28008
CMD ["sh", "-c", "uvicorn discover_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28008}"]
