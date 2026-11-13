FROM python:3.12-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 RAG_PROFILE=production
WORKDIR /app
RUN addgroup -S -g 10001 appuser \
    && adduser -S -D -H -u 10001 -G appuser appuser \
    && install -d -o appuser -g appuser -m 0700 /var/lib/rag /run/rag-parser
COPY requirements-runtime.lock .
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-runtime.lock
COPY app/ app/
COPY auth_oidc.py pdf_worker.py pdf_transport.py pdf_daemon.py production_admin.py production_store.py production_runtime.py query_intent.py rag_service.py ./
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn","app.api:app","--host","0.0.0.0","--port","8000","--workers","1","--lifespan","on","--no-proxy-headers","--no-access-log","--limit-concurrency","32","--timeout-keep-alive","5","--timeout-graceful-shutdown","20"]
