# --- Build stage ---
FROM python:3.12-slim

# Bytecode for faster start; no .pyc written into the image at runtime.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first so code changes do not bust the layer cache.
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY src ./src
COPY static ./static
COPY api.py ./
COPY eval ./eval

# Run as a non-root user. The sandbox does not isolate privileges, so this is
# the only real containment boundary the container provides.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status == 200 else 1)"

# Single worker: the pipeline is IO-bound on the LLM and pytest spawns its own
# subprocesses, so more workers mostly increases memory without more throughput.
CMD ["uvicorn", "api:app", "--host", "0.0.0.0", "--port", "8000", "--timeout-keep-alive", "75"]
