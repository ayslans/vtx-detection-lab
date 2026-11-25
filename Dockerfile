FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && adduser --disabled-password --gecos "" appuser

COPY pyproject.toml ./
COPY src/ ./src/
COPY rules/ ./rules/
COPY telemetry/ ./telemetry/
COPY tests/ ./tests/

RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev]" \
    && chown -R appuser:appuser /app

USER appuser

ENTRYPOINT ["python", "-m", "vtx_detection_lab.main"]
