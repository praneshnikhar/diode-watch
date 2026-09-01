FROM python:3.12-slim

WORKDIR /app
COPY simulator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ml /app/ml
COPY simulator/simulator /app/simulator

CMD ["python", "-m", "simulator.main"]
