FROM python:3.12-slim

WORKDIR /app

COPY shared/ /app/shared/
RUN pip install --no-cache-dir /app/shared

COPY soc2/ /app/soc2/
RUN pip install --no-cache-dir /app/soc2

EXPOSE 8003

CMD ["uvicorn", "soc2_agent.main:app", "--host", "0.0.0.0", "--port", "8003"]
