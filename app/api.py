"""FastAPI transport: trusted bearer identity, bounded inputs, safe uploads."""
from __future__ import annotations
import logging
import os
import threading
import time
from collections import defaultdict, deque
from functools import lru_cache
from pathlib import Path
from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from pydantic import BaseModel, ConfigDict, Field
from rag_service import EnterpriseRAG, Identity, TokenAuthenticator, InvalidDocument, InsufficientEvidence, ModelResponseError, MAX_UPLOAD_BYTES
from auth_oidc import OIDCAuthenticator

log = logging.getLogger("enterprise_rag.api")
app = FastAPI(title="Permission-Aware Enterprise Retrieval", version="2.0.0")

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
def backend() -> EnterpriseRAG:
    return EnterpriseRAG(os.getenv("RAG_DATA_DIR", "data"))

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

@app.post("/v1/documents/upload", status_code=201)
async def upload_document(file: UploadFile = File(...), identity: Identity = Depends(authenticated)) -> dict:
    if identity.role != "manager":
        raise HTTPException(status_code=403, detail="uploads require manager role")
    extension = Path(file.filename or "").suffix.casefold()
    if extension not in {".pdf", ".txt"}:
        raise HTTPException(status_code=415, detail="only PDF and UTF-8 text are accepted")
    try:
        payload = await file.read(MAX_UPLOAD_BYTES + 1)
        rag = backend()
        return rag.upload(payload, extension, identity.role)
    except InvalidDocument:
        raise HTTPException(status_code=400, detail="invalid or unsupported document")
    except Exception:
        log.exception("document upload failure")
        raise HTTPException(status_code=503, detail="upload unavailable")
    finally:
        await file.close()
