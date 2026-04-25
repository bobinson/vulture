FROM vulture-agent-base:latest
COPY do178c/ /app/do178c/
RUN pip install --no-cache-dir /app/do178c
EXPOSE 28009
CMD ["sh", "-c", "uvicorn do178c_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28009}"]
