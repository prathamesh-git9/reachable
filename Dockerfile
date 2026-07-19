FROM python:3.11-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1
WORKDIR /app

RUN useradd --create-home --shell /usr/sbin/nologin reachable
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels

USER reachable
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).read()"

CMD ["python", "-c", "import uvicorn; from reachable.advisories import AdvisoryDatabase; from reachable.api import create_app; uvicorn.run(create_app(AdvisoryDatabase()), host='0.0.0.0', port=8000)"]
