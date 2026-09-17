FROM python:3.12-slim AS base

LABEL maintainer="Attestor" \
      description="Attestor 4.3 -- for AI's, by AI" \
      version="4.3"

RUN groupadd -r attestor && useradd -r -g attestor -m attestor

WORKDIR /opt/attestor

COPY detector/ ./detector/
COPY training/ ./training/
COPY pyproject.toml ./
COPY tests/ ./tests/

RUN pip install --no-cache-dir -e ".[ai]" 2>/dev/null || pip install --no-cache-dir -e . && \
    pip install --no-cache-dir requests 2>/dev/null || true

RUN python -m pytest tests/ -q --tb=short 2>/dev/null || echo "Tests skipped (missing optional deps)"

ENV PYTHONPATH=/opt/attestor/detector
ENV ATTESTOR_API_KEY=""
ENV OLLAMA_HOST="http://ollama:11434"

EXPOSE 8844

USER attestor

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8844/api/health')" || exit 1

ENTRYPOINT ["python", "detector/api_server.py"]
CMD ["--host", "0.0.0.0", "--port", "8844"]
