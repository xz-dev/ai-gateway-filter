FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
COPY server.py /app/server.py
EXPOSE 8081
CMD ["python", "/app/server.py"]
