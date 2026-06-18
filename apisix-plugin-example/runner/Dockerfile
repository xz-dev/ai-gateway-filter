FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    APISIX_RUNNER_VERSION=0.2.0 \
    PYTHONPATH=/opt/apisix-python-plugin-runner

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch master https://github.com/apache/apisix-python-plugin-runner.git /opt/apisix-python-plugin-runner

WORKDIR /opt/apisix-python-plugin-runner

# The runner is not published as a wheel, so install from the official source tree.
# PyYAML 5.4.1 has build issues on current Python versions; use a modern compatible PyYAML.
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel \
    && python -m pip install --no-cache-dir a6pluginprotos==0.2.1 click==8.0.1 minicache==0.0.1 'PyYAML>=6,<7'

COPY pyproject.toml README.md /opt/privacy-gateway/
COPY src /opt/privacy-gateway/src
RUN python -m pip install --no-cache-dir -e /opt/privacy-gateway

COPY apisix-plugin-example/runner/conf/config.yaml /opt/apisix-python-plugin-runner/conf/config.yaml
COPY apisix-plugin-example/runner/apisix/plugins/privacy_gateway_guard.py /opt/apisix-python-plugin-runner/apisix/plugins/privacy_gateway_guard.py

CMD ["python", "/opt/apisix-python-plugin-runner/bin/py-runner", "start"]
