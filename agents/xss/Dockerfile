FROM vulture-agent-base:latest
COPY xss/ /app/xss/
RUN pip install --no-cache-dir /app/xss
EXPOSE 28006
CMD ["sh", "-c", "uvicorn xss_agent.main:app --host 0.0.0.0 --port ${VULTURE_AGENT_PORT:-28006}"]
