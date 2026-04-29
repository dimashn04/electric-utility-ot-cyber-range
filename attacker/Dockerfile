FROM python:3.11-slim

WORKDIR /app
ENV PYTHONPATH=/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app
COPY attacks ./attacks

CMD ["python", "attacks/unauthorized_breaker_open.py"]
