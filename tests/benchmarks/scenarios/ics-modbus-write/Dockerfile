FROM python:3.11-slim
RUN pip install --no-cache-dir 'pymodbus==3.6.9'
WORKDIR /app
COPY app/ .
CMD ["python", "plc.py"]
