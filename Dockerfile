FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY rig/ rig/
RUN pip install --no-cache-dir uv && \
    uv pip install --system -e .

COPY config.yaml .
COPY --chmod=755 healthcheck.sh .

EXPOSE 8000

CMD ["uvicorn", "rig.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
