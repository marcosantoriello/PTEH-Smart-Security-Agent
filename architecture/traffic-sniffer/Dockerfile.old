FROM python:3.11-slim

# Install system dependencies for Scapy
RUN apt-get update && apt-get install -y \
    tcpdump \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

# Create the workdir
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY sniffer/ ./sniffer/

# Create log directory
RUN mkdir -p /app/logs

# Set default environment variables
ENV SNIFFER_INTERFACE=eth0
ENV SNIFFER_COUNT=0
ENV SNIFFER_FILTER=""

# Execute the sniffer
CMD ["python", "-m", "sniffer.packet_sniffer"]
