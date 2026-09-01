FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY engine/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ml /app/ml
COPY engine/engine /app/engine

ENV PYTHONUNBUFFERED=1
CMD ["python", "-m", "engine.main"]
