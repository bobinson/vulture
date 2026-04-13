FROM vulture-agent-base:latest
COPY owasp/ /app/owasp/
RUN pip install --no-cache-dir /app/owasp
EXPOSE 28002
CMD ["sh", "-c", "uvicorn owasp_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28002}"]
