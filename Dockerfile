FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt


COPY drift_engine/ drift_engine/

COPY run.sh .
RUN chmod +x run.sh

CMD ["./run.sh"]