FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY pyproject.toml README.md /opt/privacy-gateway/
COPY src /opt/privacy-gateway/src
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -e /opt/privacy-gateway
RUN python -m spacy download en_core_web_sm

COPY apisix-plugin-example/privacy_proxy/server.py /app/server.py

EXPOSE 8080
CMD ["python", "/app/server.py"]
