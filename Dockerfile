FROM python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 RAG_PROFILE=production
WORKDIR /app
RUN useradd --system --uid 10001 --create-home appuser \
    && install -d -o appuser -g appuser -m 0700 /var/lib/rag /run/rag-parser
COPY requirements-runtime.lock .
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-runtime.lock
COPY app/ app/
COPY auth_oidc.py pdf_worker.py pdf_transport.py pdf_daemon.py production_admin.py production_store.py production_runtime.py query_intent.py rag_service.py ./
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn","app.api:app","--host","0.0.0.0","--port","8000","--workers","1","--lifespan","on","--no-proxy-headers","--no-access-log","--limit-concurrency","32","--timeout-keep-alive","5","--timeout-graceful-shutdown","20"]
