FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent.py .
COPY knowledge_base/ ./knowledge_base/

RUN mkdir -p /app/chroma_db
RUN mkdir -p /app/logs

CMD ["python", "agent.py"]
