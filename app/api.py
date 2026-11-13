"""FastAPI transport: trusted bearer identity, bounded inputs, safe uploads."""
from __future__ import annotations
import logging
import os
import threading
import time
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from python_multipart.exceptions import MultipartParseError
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.formparsers import MultiPartException
from rag_service import EnterpriseRAG, Identity, TokenAuthenticator, InvalidDocument, InsufficientEvidence, ModelResponseError, MAX_UPLOAD_BYTES
from auth_oidc import OIDCAuthenticator

log = logging.getLogger("enterprise_rag.api")
app = FastAPI(title="Permission-Aware Enterprise Retrieval", version="2.0.0")
app.mount("/ui", StaticFiles(directory=Path(__file__).with_name("static"), html=True), name="ui")
MAX_MULTIPART_BYTES = MAX_UPLOAD_BYTES + 65_536

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
        return OIDCAuthenticator()
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

    def check(self, subject: str) -> bool:
        now = time.monotonic()
        with self.lock:
            queue = self.recent[subject]
            while queue and queue[0] < now - 60:
                queue.popleft()
            if len(queue) >= 30:
                return False
            queue.append(now)
        return True

rate_gate = RateGate()

def authenticated(authorization: str | None = Header(default=None)) -> Identity:
    try:
        auth = authenticator()
    except (RuntimeError, ValueError, OSError):
        log.exception("service not configured")
        raise HTTPException(status_code=503, detail="service is unavailable")
    identity = auth.authenticate(authorization)
    if identity is None:
        raise HTTPException(status_code=401, detail="authentication required",
                            headers={"WWW-Authenticate": "Bearer"})
    if not rate_gate.check(identity.subject):
        raise HTTPException(status_code=429, detail="rate limit exceeded")
    return identity

@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}

@app.post("/v1/query")
def query(body: QueryRequest, identity: Identity = Depends(authenticated)) -> dict:
    try:
        rag = backend()
        return rag.query(body.query, identity)
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
            return backend().upload(payload, extension, identity.role)

        return await run_in_threadpool(index_document)
    except (StarletteHTTPException, MultiPartException, MultipartParseError) as exc:
        if limit_exceeded:
            raise HTTPException(status_code=413, detail="multipart request exceeds limit") from None
        if isinstance(exc, StarletteHTTPException):
            if exc.status_code != 400:
                raise
        raise HTTPException(status_code=400, detail="invalid multipart request") from None
    except InvalidDocument:
        raise HTTPException(status_code=400, detail="invalid or unsupported document")
    except Exception:
        log.exception("document upload failure")
        raise HTTPException(status_code=503, detail="upload unavailable")
