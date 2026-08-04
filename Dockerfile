FROM python:3.12-slim

WORKDIR /app


RUN apt-get update && apt-get install -y wget unzip \
    && wget https://releases.hashicorp.com/terraform/1.5.7/terraform_1.5.7_linux_amd64.zip \
    && unzip terraform_1.5.7_linux_amd64.zip \
    && mv terraform /usr/local/bin/ \
    && rm terraform_1.5.7_linux_amd64.zip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY drift_engine/ drift_engine/

COPY run.sh .
RUN chmod +x run.sh

CMD ["./run.sh"]