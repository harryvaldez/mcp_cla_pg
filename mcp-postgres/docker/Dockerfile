FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml /app/pyproject.toml
COPY src /app/src

RUN python -m pip install --upgrade pip && \
    pip install --prefix=/install .

FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FASTMCP_HOST=0.0.0.0 \
    FASTMCP_PORT=8080

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin mcpuser

WORKDIR /app
COPY --from=builder /install /usr/local
COPY config /app/config
COPY policy /app/policy
COPY src /app/src

RUN mkdir -p /var/log/mcp && chown -R mcpuser:mcpuser /var/log/mcp /app

USER mcpuser

EXPOSE 8080

ENTRYPOINT ["uvicorn", "src.server:app", "--host", "0.0.0.0", "--port", "8080"]
