FROM python:3.12-slim

WORKDIR /app

COPY shared/ /app/shared/
RUN pip install --no-cache-dir /app/shared

COPY owasp/ /app/owasp/
RUN pip install --no-cache-dir /app/owasp

EXPOSE 8002

CMD ["uvicorn", "owasp_agent.main:app", "--host", "0.0.0.0", "--port", "8002"]
