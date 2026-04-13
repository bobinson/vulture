FROM vulture-agent-base:latest
COPY cwe/ /app/cwe/
RUN pip install --no-cache-dir /app/cwe
EXPOSE 28004
CMD ["sh", "-c", "uvicorn cwe_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28004}"]
