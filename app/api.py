"""HTTP API for enterprise RBAC RAG."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from rbac_rag import EnterpriseRAG, RBACEnforcer

app = FastAPI(
    title="Enterprise RAG System",
    version="1.0.0",
    description="Hybrid RAG with role-based access control and cited answers",
)


class QueryRequest(BaseModel):
    user_id: str = Field(..., min_length=1, description="User id from users.json")
    query: str = Field(..., min_length=1, max_length=4000)

_ui = Path(__file__).resolve().parent / "static"
if _ui.is_dir():
    app.mount("/ui", StaticFiles(directory=str(_ui), html=True), name="rag-ui")


@lru_cache(maxsize=1)
def _system() -> RBACEnforcer:
    return RBACEnforcer(EnterpriseRAG())


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/query")
def query(body: QueryRequest) -> dict:
    """Run an RBAC-filtered RAG query."""
    try:
        return _system().query(body.user_id, body.query)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/v1/documents/upload")
async def upload_document(file: UploadFile = File(...)) -> dict:
    """Store an uploaded text document for future indexing (metadata only in v1)."""
    content = (await file.read()).decode("utf-8", errors="replace")
    if len(content) > 500_000:
        raise HTTPException(status_code=413, detail="file too large")
    upload_dir = Path(__file__).resolve().parents[1] / "data" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    path = upload_dir / (file.filename or "upload.txt")
    path.write_text(content, encoding="utf-8")
    return {"stored": str(path), "bytes": len(content), "status": "stored"}


@app.get("/v1/users")
def list_users() -> dict:
    """List demo users (ids only) for the interactive docs."""
    users = _system().users
    return {"users": sorted(users.keys())}
