FROM python:3.12-slim

WORKDIR /app

# Install system utilities and curl for health probes
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ /app/backend/
COPY bin/ /app/bin/
COPY config.example.yaml config.yaml app.py /app/

RUN chmod +x /app/bin/harvester /app/app.py && \
    ln -sf /app/bin/harvester /usr/local/bin/harvester

ENV PYTHONPATH=/app
ENV PORT=8000

EXPOSE 8000

CMD ["python", "app.py"]
