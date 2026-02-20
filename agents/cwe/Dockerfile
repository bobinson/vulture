FROM python:3.12-slim

WORKDIR /app

COPY shared/ /app/shared/
RUN pip install --no-cache-dir /app/shared

COPY cwe/ /app/cwe/
RUN pip install --no-cache-dir /app/cwe

EXPOSE 8004

CMD ["uvicorn", "cwe_agent.main:app", "--host", "0.0.0.0", "--port", "8004"]
