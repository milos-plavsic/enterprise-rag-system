# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
FROM python:3.12-alpine3.24@sha256:c5ba3deef00c7758561a0f03c26f44f10589263d40e732b8748e0d1f38f6dd89 AS patched
# Keep this profile on linux/amd64 until the package digests and smoke tests cover other architectures.
ADD --checksum=sha256:7b05bc778b8b25cd880835b40114182bd4d1581717504d0129c810c0a14291cb https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/zlib-1.4-r0.apk /tmp/zlib.apk
ADD --checksum=sha256:fad5b46a953e6a37a1bb61a84538fa08ecb6a07816f439eb06f2735aebfcbfbf https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/krb5-libs-1.22.3-r0.apk /tmp/krb5-libs.apk
# v3.24 does not yet provide SQLite 3.54.1. Install only the verified upstream Alpine library package, not the CLI.
ADD --checksum=sha256:5dfd76936e795efd988d6bad4949b8d20c410d6dc9dd256da884111f668f3915 https://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/sqlite-libs-3.54.1-r0.apk /tmp/sqlite-libs.apk
RUN test "$(apk --print-arch)" = x86_64 \
    && apk verify /tmp/zlib.apk /tmp/krb5-libs.apk /tmp/sqlite-libs.apk \
    && apk add --no-network --no-cache /tmp/zlib.apk /tmp/krb5-libs.apk /tmp/sqlite-libs.apk \
    && rm /tmp/zlib.apk /tmp/krb5-libs.apk /tmp/sqlite-libs.apk
# Install exact vendor-signed stable OpenSSL package revisions together.
# The high/critical scan remains mandatory; this revision does not resolve every advisory.
ADD --checksum=sha256:042026082cc9bc7872d1baa81755c50efa70b05f03b5369fdc5f0a1303009720 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libcrypto3-3.5.9-r1.apk /tmp/libcrypto3.apk
ADD --checksum=sha256:18c5778cbe52e1991303f8531970b05d4e6e036ea08349322f7422f42a689dc7 https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/libssl3-3.5.9-r1.apk /tmp/libssl3.apk
RUN apk verify /tmp/libcrypto3.apk /tmp/libssl3.apk \
    && apk add --no-network --no-cache /tmp/libcrypto3.apk /tmp/libssl3.apk \
    && apk info -e 'libcrypto3=3.5.9-r1' 'libssl3=3.5.9-r1' \
    && rm /tmp/libcrypto3.apk /tmp/libssl3.apk

FROM patched
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 RAG_PROFILE=production
WORKDIR /app
RUN addgroup -S -g 10001 appuser \
    && adduser -S -D -H -u 10001 -G appuser appuser \
    && install -d -o appuser -g appuser -m 0700 /var/lib/rag /run/rag-parser
COPY requirements-runtime.lock .
RUN python -m pip install --no-cache-dir --only-binary=:all: --require-hashes -r requirements-runtime.lock
COPY app/ app/
COPY identity_policy.py disaster_recovery.py document_source.py reference_ranking.py reference_answer.py auth_oidc.py pdf_worker.py pdf_transport.py pdf_daemon.py production_admin.py production_store.py production_runtime.py query_intent.py rag_service.py ./
USER 10001:10001
EXPOSE 8000
CMD ["uvicorn","app.api:app","--host","0.0.0.0","--port","8000","--workers","1","--http","h11","--lifespan","on","--no-proxy-headers","--no-access-log","--limit-concurrency","32","--timeout-keep-alive","5","--timeout-graceful-shutdown","20"]
