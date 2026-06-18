FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends tesseract-ocr libgl1 libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md /opt/privacy-gateway/
COPY src /opt/privacy-gateway/src
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -e /opt/privacy-gateway
RUN python -m spacy download en_core_web_sm

COPY apisix-plugin-example/privacy_proxy/server.py /app/server.py

EXPOSE 8080
CMD ["python", "/app/server.py"]
