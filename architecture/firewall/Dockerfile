FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    tcpdump \
    libpcap-dev \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY firewall.py .
COPY enforcer.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh
RUN mkdir -p /app/logs /shared/pcap

CMD ["./entrypoint.sh"]


