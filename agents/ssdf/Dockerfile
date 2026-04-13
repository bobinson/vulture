FROM vulture-agent-base:latest
COPY ssdf/ /app/ssdf/
RUN pip install --no-cache-dir /app/ssdf
EXPOSE 28007
CMD ["sh", "-c", "uvicorn ssdf_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28007}"]
