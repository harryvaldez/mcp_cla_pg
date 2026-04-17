FROM python:3.13-slim AS builder

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --prefix=/install -r /app/requirements.txt


FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY --from=builder /install /usr/local
COPY server.py /app/server.py

RUN useradd --create-home --uid 10001 appuser && \
    chown -R appuser:appuser /app
USER appuser

ENV MCP_TRANSPORT=http
ENV MCP_HOST=0.0.0.0
ENV MCP_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request, sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=5).getcode() == 200 else 1)"

CMD ["python", "/app/server.py"]

