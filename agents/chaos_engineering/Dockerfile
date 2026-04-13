FROM vulture-agent-base:latest
COPY chaos_engineering/ /app/chaos/
RUN pip install --no-cache-dir /app/chaos
EXPOSE 28001
CMD ["sh", "-c", "uvicorn chaos_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28001}"]
