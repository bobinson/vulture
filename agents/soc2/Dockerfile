FROM vulture-agent-base:latest
COPY soc2/ /app/soc2/
RUN pip install --no-cache-dir /app/soc2
EXPOSE 28003
CMD ["sh", "-c", "uvicorn soc2_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28003}"]
