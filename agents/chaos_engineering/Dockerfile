FROM python:3.12-slim

WORKDIR /app

COPY shared/ /app/shared/
RUN pip install --no-cache-dir /app/shared

COPY chaos_engineering/ /app/chaos/
RUN pip install --no-cache-dir /app/chaos

EXPOSE 8001

CMD ["uvicorn", "chaos_agent.main:app", "--host", "0.0.0.0", "--port", "8001"]
