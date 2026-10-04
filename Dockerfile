FROM python:3.12-slim

WORKDIR /app

# Install ca-certificates and curl for health probes
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ /app/src/
COPY bin/ /app/bin/
COPY app.py /app/

RUN chmod +x /app/bin/harvester /app/app.py && \
    ln -sf /app/bin/harvester /usr/local/bin/harvester

CMD ["python", "app.py"]
