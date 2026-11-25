FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src/ ./src/
COPY rules/ ./rules/
COPY telemetry/ ./telemetry/
COPY tests/ ./tests/

RUN pip install --no-cache-dir -e ".[dev]"

ENTRYPOINT ["python", "-m", "vtx_detection_lab.main"]
