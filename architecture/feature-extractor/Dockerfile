FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY libs/NTLFlowLyzer ./libs/NTLFlowLyzer

WORKDIR /app/libs/NTLFlowLyzer
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install .

WORKDIR /app

COPY extractor.py .
COPY config.json .

RUN mkdir -p /app/input /app/output

CMD ["python", "extractor.py"]
