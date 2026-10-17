FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

COPY worker/requirements.txt /app/worker/requirements.txt
RUN pip install --no-cache-dir -r /app/worker/requirements.txt

COPY config.example.yaml /app/config.example.yaml
COPY config.example.yaml /app/config.yaml
COPY worker/ /app/worker/

ENV PYTHONPATH=/app
ENV PORT=8001
ENV MODE=batch

ENTRYPOINT ["python", "-m", "worker.app"]
CMD []
