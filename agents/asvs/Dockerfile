FROM vulture-agent-base:latest
COPY asvs/ /app/asvs/
RUN pip install --no-cache-dir /app/asvs
EXPOSE 28010
CMD ["sh", "-c", "uvicorn asvs_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28010}"]
