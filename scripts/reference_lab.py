"""Prepare a private local lab; does not start services or download models implicitly."""
from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
MODEL_REV = "9217f5db79a29953eb74d5343926648285ec7e67"
MODEL_SHA = "74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db"
MODEL_SIZE = 491400032
MODEL_URL = ("https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/" + MODEL_REV
             + "/qwen2.5-0.5b-instruct-q4_k_m.gguf")


def prepare(path: Path) -> None:
    path_text = str(path)
    if not path_text or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./-" for c in path_text):
        raise ValueError("use a lab path without spaces or shell metacharacters")
    os.umask(0o077)
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    subprocess.run([sys.executable, str(ROOT / "reference/realm.py"), str(path / "keycloak")], check=True)
    subprocess.run([sys.executable, str(ROOT / "reference/corpus.py"), str(path / "source"), "1"], check=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-days", "30",
                    "-subj", "/CN=Juniper Reference Lab", "-addext", "subjectAltName=DNS:localhost,DNS:idp",
                    "-keyout", str(path / "key.pem"), "-out", str(path / "cert.pem")], check=True, capture_output=True)
    (path / "audit-key").write_text(secrets.token_hex(32), encoding="utf-8")
    (path / "data").mkdir()
    (path / "models").mkdir()
    # Rootful Linux Docker uses the image's numeric UIDs. Parent directory remains 0700.
    for name in ("key.pem", "cert.pem", "audit-key", "keycloak/juniper-realm.json", "source/manifest.json"):
        (path / name).chmod(0o444)
    (path / "source").chmod(0o755)
    for item in (path / "source").glob("*.txt"):
        item.chmod(0o444)
    (path / "models").chmod(0o755)
    (path / "compose.env").write_text(f"RAG_LAB_PATH={path_text}\nRAG_DATA_PATH={path_text}/data\n"
                                      f"RAG_AUDIT_KEY_PATH={path_text}/audit-key\nRAG_IMAGE=juniper-rag:local\n"
                                      "RAG_OIDC_ISSUER=https://localhost:8443/realms/juniper\n"
                                      "RAG_OIDC_AUDIENCE=juniper-rag\nRAG_OIDC_JWKS_URL=https://idp:8443/realms/juniper/protocol/openid-connect/certs\n",
                                      encoding="utf-8")


def model(path: Path) -> None:
    output = path / "models/reference.gguf"
    if output.exists():
        raise FileExistsError(output)
    digest, count = hashlib.sha256(), 0
    with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as stream:
        stage = Path(stream.name)
        try:
            with urlopen(MODEL_URL, timeout=60) as response:
                while data := response.read(1024 * 1024):
                    count += len(data)
                    if count > MODEL_SIZE:
                        raise RuntimeError("model size exceeded")
                    digest.update(data)
                    stream.write(data)
            if count != MODEL_SIZE or digest.hexdigest() != MODEL_SHA:
                raise RuntimeError("model failed integrity verification")
            stream.flush()
            stage.chmod(0o444)
            os.link(stage, output)
        finally:
            stage.unlink(missing_ok=True)


if __name__ == "__main__":
    {"prepare": prepare, "model": model}[sys.argv[1]](Path(sys.argv[2]).resolve())
