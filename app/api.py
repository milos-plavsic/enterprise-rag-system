"""FastAPI transport: trusted bearer identity, bounded inputs, safe uploads."""
from __future__ import annotations
import logging
import os
import threading
import time
import uuid
from contextlib import asynccontextmanager
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from python_multipart.exceptions import MultipartParseError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException
from rag_service import EnterpriseRAG, Identity, TokenAuthenticator, InvalidDocument, InsufficientEvidence, ModelResponseError, MAX_UPLOAD_BYTES
from auth_oidc import OIDCAuthenticator
from jwt.exceptions import PyJWKClientConnectionError
from pdf_transport import parser_ready
from production_runtime import Settings, audit, deployment_lock, production_mode, store
from rag_service import extract_pages

log = logging.getLogger("enterprise_rag.api")
@asynccontextmanager
async def lifespan(application: FastAPI):
    if not production_mode():
        yield
        return
    settings = Settings.load()
    with deployment_lock(settings.database):
        application.state.production = settings
        try:
            await run_in_threadpool(store(settings).readiness)
            # Startup verifies static identity configuration. Readiness exercises JWKS.
            authenticator()
            yield
        finally:
            application.state.production = None


app = FastAPI(title="Permission-Aware Enterprise Retrieval", version="2.1.0", lifespan=lifespan)
class DemoStatic(StaticFiles):
    async def get_response(self, path, scope):
        if production_mode():
            return JSONResponse(status_code=404, content={"detail": "not found"})
        return await super().get_response(path, scope)


app.mount("/ui", DemoStatic(directory=Path(__file__).with_name("static"), html=True), name="ui")
MAX_MULTIPART_BYTES = MAX_UPLOAD_BYTES + 65_536
MAX_QUERY_BODY = 32_768


@app.exception_handler(RequestValidationError)
async def validation_error(_request: Request, _exc: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "invalid request"})


class QueryBodyLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/v1/query" or scope["method"] != "POST":
            await self.app(scope, receive, send)
            return
        size = 0

        async def bounded():
            nonlocal size
            message = await receive()
            size += len(message.get("body", b""))
            if size > MAX_QUERY_BODY:
                raise HTTPException(status_code=413, detail="query body exceeds limit")
            return message

        await self.app(scope, bounded, send)


app.add_middleware(QueryBodyLimit)


def active_settings(request: Request) -> Settings | None:
    if not production_mode():
        return None
    settings = getattr(request.app.state, "production", None)
    if settings is None:
        raise HTTPException(status_code=503, detail="service is unavailable")
    return settings


@app.middleware("http")
async def request_audit(request: Request, call_next):
    if not production_mode() or not request.url.path.startswith("/v1/"):
        return await call_next(request)
    request.state.request_id = uuid.uuid4().hex
    started = time.monotonic()
    response = await call_next(request)
    settings = getattr(request.app.state, "production", None)
    if settings is None:
        return response
    event = {("POST", "/v1/query"): "query", ("POST", "/v1/documents/upload"): "upload"}.get(
        (request.method, request.url.path), "document_delete" if request.method == "DELETE" else "other_api")
    audit(settings, event=event, outcome=str(response.status_code),
          subject=getattr(request.state, "subject", None), request_id=request.state.request_id,
          sources=getattr(request.state, "sources", None), elapsed_ms=round((time.monotonic() - started) * 1000))
    response.headers["X-Request-ID"] = request.state.request_id
    response.headers["Cache-Control"] = "no-store"
    return response

class QueryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=2000)

@lru_cache(maxsize=1)
def authenticator() -> TokenAuthenticator | OIDCAuthenticator:
    oidc_config = (
        os.getenv("RAG_OIDC_JWKS_URL", ""),
        os.getenv("RAG_OIDC_ISSUER", ""),
        os.getenv("RAG_OIDC_AUDIENCE", ""),
    )
    if any(oidc_config):
        if not all(oidc_config):
            raise RuntimeError("OIDC configuration must include JWKS URL, issuer and audience")
        if os.getenv("RAG_API_TOKENS_JSON"):
            raise RuntimeError("choose OIDC or demo bearer tokens, not both")
        return OIDCAuthenticator(production=production_mode())
    if production_mode():
        raise RuntimeError("production requires OIDC configuration")
    return TokenAuthenticator()

@lru_cache(maxsize=1)
def _backend() -> EnterpriseRAG:
    return EnterpriseRAG(os.getenv("RAG_DATA_DIR", "data"))

_backend_lock = threading.Lock()


def backend() -> EnterpriseRAG:
    # lru_cache alone permits concurrent initialisations on a cache miss.
    with _backend_lock:
        return _backend()


backend.cache_clear = _backend.cache_clear

class RateGate:
    """Local burst limit; distributed deployment also needs a gateway rate limit."""
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.recent: dict[str, deque[float]] = defaultdict(deque)
        self.last_cleanup = 0.0

    def check(self, subject: str) -> bool:
        now = time.monotonic()
        with self.lock:
            if now - self.last_cleanup >= 60 or subject not in self.recent and len(self.recent) >= 4096:
                for key, timestamps in list(self.recent.items()):
                    if not timestamps or timestamps[-1] <= now - 60:
                        del self.recent[key]
                self.last_cleanup = now
            if subject not in self.recent and len(self.recent) >= 4096:
                return False
            queue = self.recent[subject]
            while queue and queue[0] < now - 60:
                queue.popleft()
            if len(queue) >= 30:
                return False
            queue.append(now)
        return True

rate_gate = RateGate()
query_slots = threading.BoundedSemaphore(4)
upload_slots = threading.BoundedSemaphore(2)

def authenticated(request: Request, authorization: str | None = Header(default=None)) -> Identity:
    settings = active_settings(request)
    try:
        auth = authenticator()
    except (RuntimeError, ValueError, OSError):
        log.exception("service not configured")
        raise HTTPException(status_code=503, detail="service is unavailable")
    try:
        identity = auth.authenticate(authorization)
    except PyJWKClientConnectionError:
        raise HTTPException(status_code=503, detail="identity service unavailable") from None
    if identity is None:
        raise HTTPException(status_code=401, detail="authentication required",
                            headers={"WWW-Authenticate": "Bearer"})
    if settings is not None:
        request.state.subject = identity.subject
        try:
            entitled = store(settings).entitled(identity)
        except Exception:
            log.error("production entitlement check failed")
            raise HTTPException(status_code=503, detail="service is unavailable") from None
        if not entitled:
            raise HTTPException(status_code=403, detail="access denied")
    if not rate_gate.check(identity.subject):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    return identity

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.get("/ready")
def readiness(request: Request) -> dict[str, str]:
    try:
        settings = active_settings(request)
        auth = authenticator()
        if settings:
            store(settings).readiness()
            auth.readiness()
            parser_ready(settings.parser_socket)
        else:
            backend()
    except Exception:
        raise HTTPException(status_code=503, detail="service is not ready") from None
    return {"status": "ready"}


@app.post("/v1/query")
def query(request: Request, body: QueryRequest, identity: Identity = Depends(authenticated)) -> dict:
    try:
        settings = active_settings(request)
        if settings:
            if not query_slots.acquire(blocking=False):
                raise HTTPException(status_code=503, detail="query capacity reached", headers={"Retry-After": "1"})
            try:
                response = store(settings).query(body.query, identity)
            finally:
                query_slots.release()
            request.state.sources = [citation["source"] for citation in response["citations"]]
            return response
        return backend().query(body.query, identity)
    except HTTPException:
        raise
    except PermissionError:
        raise HTTPException(status_code=403, detail="requested source not permitted")
    except InsufficientEvidence:
        return {"status": "abstained",
                "answer": "The requested operation is unsupported or insufficiently specified.",
                "citations": [], "evidence": [], "confidence": None}
    except ModelResponseError:
        raise HTTPException(status_code=502, detail="model response rejected")
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid query")
    except Exception:
        if production_mode():
            log.error("query failure")
        else:
            log.exception("query failure")
        raise HTTPException(status_code=503, detail="query unavailable")

@app.post(
    "/v1/documents/upload", status_code=201,
    openapi_extra={"requestBody": {"required": True, "content": {"multipart/form-data": {
        "schema": {"type": "object", "required": ["file"],
                   "properties": {"file": {"type": "string", "format": "binary"}}},
    }}}},
)
async def upload_document(request: Request, identity: Identity = Depends(authenticated)) -> dict:
    if identity.role != "manager":
        raise HTTPException(status_code=403, detail="uploads require manager role")
    settings = active_settings(request)
    if request.headers.get("content-type", "").partition(";")[0].strip().lower() != "multipart/form-data":
        raise HTTPException(status_code=415, detail="multipart/form-data is required")

    # Authorise before reading the body. Limit bytes as the multipart parser
    # receives them, including when the caller omits Content-Length.
    body_bytes = 0
    limit_exceeded = False

    async def bounded_receive():
        nonlocal body_bytes, limit_exceeded
        message = await request.receive()
        body_bytes += len(message.get("body", b""))
        if body_bytes > MAX_MULTIPART_BYTES:
            limit_exceeded = True
            # Starlette closes parser-owned temporary files on this exception.
            raise MultiPartException("multipart request exceeds limit")
        return message

    bounded = Request(request.scope, receive=bounded_receive)
    if settings and not upload_slots.acquire(blocking=False):
        raise HTTPException(status_code=503, detail="upload capacity reached", headers={"Retry-After": "1"})
    try:
        async with bounded.form(max_files=1, max_fields=0) as form:
            file = form.get("file")
            if not isinstance(file, UploadFile):
                raise HTTPException(status_code=422, detail="exactly one file is required")
            extension = Path(file.filename or "").suffix.casefold()
            if extension not in {".pdf", ".txt"}:
                raise HTTPException(status_code=415, detail="only PDF and UTF-8 text are accepted")
            payload = await file.read(MAX_UPLOAD_BYTES + 1)

        def index_document():
            if settings:
                pages = extract_pages(payload, extension, parser_socket=settings.parser_socket)
                return store(settings).upload(identity, payload, pages)
            return backend().upload(payload, extension, identity.role)

        response = await run_in_threadpool(index_document)
        if settings:
            request.state.sources = [response["source_id"]]
        return response
    except (StarletteHTTPException, MultiPartException, MultipartParseError) as exc:
        if limit_exceeded:
            raise HTTPException(status_code=413, detail="multipart request exceeds limit") from None
        if isinstance(exc, StarletteHTTPException):
            if exc.status_code != 400:
                raise
        raise HTTPException(status_code=400, detail="invalid multipart request") from None
    except InvalidDocument:
        raise HTTPException(status_code=400, detail="invalid or unsupported document") from None
    except PermissionError:
        raise HTTPException(status_code=403, detail="access denied") from None
    except Exception:
        if production_mode():
            log.error("document upload failure")
        else:
            log.exception("document upload failure")
        raise HTTPException(status_code=503, detail="upload unavailable")
    finally:
        if settings:
            upload_slots.release()


@app.delete("/v1/documents/{source}", status_code=204)
def delete_document(request: Request, source: uuid.UUID, identity: Identity = Depends(authenticated)) -> None:
    settings = active_settings(request)
    try:
        deleted = settings and store(settings).delete(source.hex, identity)
    except PermissionError:
        raise HTTPException(status_code=403, detail="access denied") from None
    except Exception:
        log.error("document delete failure")
        raise HTTPException(status_code=503, detail="delete unavailable") from None
    if not deleted:
        raise HTTPException(status_code=404, detail="document not found")
    request.state.sources = [source.hex]
