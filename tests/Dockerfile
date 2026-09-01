FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY engine/requirements.txt /app/engine-requirements.txt
COPY simulator/requirements.txt /app/sim-requirements.txt
COPY ml/requirements.txt /app/ml-requirements.txt
RUN pip install --no-cache-dir \
    -r /app/engine-requirements.txt \
    -r /app/ml-requirements.txt \
    -r /app/sim-requirements.txt \
    pytest

COPY . /app
ENV PYTHONPATH=/app
CMD ["pytest", "-q", "--tb=short"]
