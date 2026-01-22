FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-chache-dir -r requirements.txt

COPY agent.py .

CMD ["python", "agent.py"]
