FROM python:3.11-slim
RUN pip install --no-cache-dir flask==3.0.3
WORKDIR /app
COPY server.py .
CMD ["python", "server.py"]
