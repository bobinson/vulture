FROM vulture-agent-base:latest
COPY prove/ /app/prove/
RUN pip install --no-cache-dir /app/prove
EXPOSE 28005
CMD ["sh", "-c", "uvicorn prove_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28005}"]
