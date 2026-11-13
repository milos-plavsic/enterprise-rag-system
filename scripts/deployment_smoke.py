"""Exercise the exact Linux Compose profile using only generated test material."""
from __future__ import annotations

import base64
import concurrent.futures
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ISSUER = "https://idp:8443"
AUDIENCE = "compose-smoke"


def b64(value: bytes) -> bytes:
    return base64.urlsafe_b64encode(value).rstrip(b"=")


def request(url, path, *, method="GET", token=None, body=None, content_type=None):
    headers = {}
    if token:
        headers["Authorization"] = "Bearer " + token
    if content_type:
        headers["Content-Type"] = content_type
    if isinstance(body, dict):
        body = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    try:
        with urllib.request.urlopen(urllib.request.Request(url + path, body, headers, method=method), timeout=12) as result:
            return result.status, json.loads(result.read()) if result.status != 204 else None
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def pdf_fixture() -> bytes:
    text = b"BT /F1 12 Tf 50 750 Td (Larch inventory attestation.) Tj ET"
    objects = [b"<< /Type /Catalog /Pages 2 0 R >>",
               b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
               b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
               b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
               b"<< /Length " + str(len(text)).encode() + b" >>\nstream\n" + text + b"\nendstream"]
    result = bytearray(b"%PDF-1.4\n")
    offsets = []
    for number, entry in enumerate(objects, 1):
        offsets.append(len(result))
        result.extend(f"{number} 0 obj\n".encode() + entry + b"\nendobj\n")
    xref = len(result)
    result.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets:
        result.extend(f"{offset:010} 00000 n \n".encode())
    result.extend(f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(result)


def main(image: str) -> None:
    with tempfile.TemporaryDirectory(prefix="rag-smoke-") as directory:
        root = Path(directory)
        data, fixture = root / "data", root / "fixture"
        for item in (data, fixture, fixture / "keys"):
            item.mkdir(mode=0o755)
        # Test-runner-only directory. The production runbook requires UID-owned 0700 storage.
        data.chmod(0o777)
        key = fixture / "idp.key"
        cert = fixture / "cert.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=idp", "-addext", "subjectAltName=DNS:idp", "-keyout", str(key),
                        "-out", str(cert)], check=True, capture_output=True)
        # Synthetic fixture runs as a different UID inside Docker.
        key.chmod(0o444)
        modulus = subprocess.check_output(["openssl", "rsa", "-in", str(key), "-noout", "-modulus"])
        (fixture / "keys" / "jwks").write_text(json.dumps({"keys": [
            {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "smoke",
             "n": b64(bytes.fromhex(modulus.decode().strip().split("=", 1)[1])).decode(), "e": "AQAB"}]}))
        (fixture / "source.txt").write_text("Cedar reference manual for quarterly close.")
        audit = root / "audit-key"
        audit.write_text(os.urandom(32).hex())
        audit.chmod(0o444)
        override = root / "override.yml"
        override.write_text(f'''services:
  api:
    environment:
      SSL_CERT_FILE: /fixture/cert.pem
    volumes:
      - {fixture / "cert.pem"}:/fixture/cert.pem:ro
      - {fixture / "source.txt"}:/fixture/source.txt:ro
  idp:
    image: {image}
    command: ["python", "/fixture/smoke_idp.py"]
    volumes:
      - {fixture}:/fixture:ro
      - {ROOT / "scripts/smoke_idp.py"}:/fixture/smoke_idp.py:ro
''')
        env = {**os.environ, "RAG_IMAGE": image, "RAG_PORT": "0", "RAG_DATA_PATH": str(data),
               "RAG_AUDIT_KEY_PATH": str(audit), "RAG_OIDC_ISSUER": ISSUER,
               "RAG_OIDC_AUDIENCE": AUDIENCE, "RAG_OIDC_JWKS_URL": ISSUER + "/jwks"}
        project = "rag-smoke-" + uuid.uuid4().hex[:10]
        prefix = ["docker", "compose", "-p", project, "-f", str(ROOT / "compose.production.yml"), "-f", str(override)]

        def docker(*args, output=False, check=True):
            return subprocess.run([*prefix, *args], env=env, check=check, text=True,
                                  capture_output=output, timeout=90).stdout

        def admin(*args):
            return docker("run", "--rm", "--no-deps", "api", "python", "production_admin.py", *args, output=True)

        def bearer(subject, role):
            issued = int(time.time())
            body = b".".join(b64(json.dumps(item).encode()) for item in (
                {"alg": "RS256", "typ": "at+jwt", "kid": "smoke"},
                {"iss": ISSUER, "aud": AUDIENCE, "sub": subject, "enterprise_role": role,
                 "iat": issued, "exp": issued + 180}))
            signature = subprocess.check_output(["openssl", "dgst", "-sha256", "-sign", str(key)], input=body)
            return (body + b"." + b64(signature)).decode()

        def ready():
            for _ in range(30):
                try:
                    address = docker("port", "api", "8000", output=True).strip()
                    url = "http://" + address
                    if request(url, "/ready")[0] == 200:
                        return url
                except (OSError, ValueError, subprocess.CalledProcessError):
                    pass
                time.sleep(1)
            raise RuntimeError("Compose profile did not become ready")

        def ask(url, token, text):
            return request(url, "/v1/query", method="POST", token=token, body={"query": text})

        try:
            admin("init")
            admin("grant", "smoke-a", "manager")
            admin("grant", "smoke-b", "manager")
            admin("publish", "/fixture/source.txt", "--title", "Cedar", "--role", "analyst")
            docker("up", "-d")
            url = ready()
            token_a, token_b = bearer("smoke-a", "manager"), bearer("smoke-b", "manager")
            boundary = "rag-smoke-test-boundary"
            body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="reference.txt"'
                    f'\r\nContent-Type: text/plain\r\n\r\nJuniper maintenance window.\r\n--{boundary}--\r\n').encode()
            status, result = request(url, "/v1/documents/upload", method="POST", token=token_a, body=body,
                                     content_type=f"multipart/form-data; boundary={boundary}")
            assert status == 201, (status, result)
            source = result["source_id"]
            assert ask(url, token_a, "Juniper")[1]["citations"][0]["source"] == source
            assert ask(url, token_b, "Juniper")[1]["status"] == "abstained"
            assert ask(url, token_a, "Cedar")[1]["status"] == "abstained"
            pdf_body = (f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="reference.pdf"'
                        '\r\nContent-Type: application/pdf\r\n\r\n').encode() + pdf_fixture() + f"\r\n--{boundary}--\r\n".encode()
            status, result = request(url, "/v1/documents/upload", method="POST", token=token_a, body=pdf_body,
                                     content_type=f"multipart/form-data; boundary={boundary}")
            assert status == 201, (status, result)
            assert ask(url, token_a, "Larch")[1]["citations"][0]["source"] == result["source_id"]
            started = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                outcomes = list(pool.map(lambda _index: ask(url, token_a, "Juniper")[0], range(12)))
            assert outcomes == [200] * 12, outcomes
            print(f"Synthetic 12-request smoke batch completed in {time.monotonic() - started:.3f}s")
            admin("backup", "/var/lib/rag/snapshot.sqlite3")
            assert stat.S_IMODE((data / "snapshot.sqlite3").stat().st_mode) == 0o600
            docker("up", "-d", "--no-deps", "--force-recreate", "api")
            url = ready()
            assert ask(url, token_a, "Juniper")[1]["citations"][0]["source"] == source
            admin("revoke", "smoke-a")
            assert ask(url, token_a, "Juniper")[0] == 403
            docker("stop", "api")
            docker("run", "--rm", "--no-deps", "api", "python", "production_admin.py",
                   "--database", "/var/lib/rag/snapshot.sqlite3", "quarantine-restored-grants")
            docker("run", "--rm", "--no-deps", "api", "python", "-c",
                   "from pathlib import Path; p=Path('/var/lib/rag'); "
                   "assert not (p/'catalog.sqlite3-wal').exists(); "
                   "(p/'snapshot.sqlite3').replace(p/'catalog.sqlite3')")
            docker("up", "-d", "--no-deps", "api")
            url = ready()
            assert ask(url, token_a, "Juniper")[0] == 403
            admin("grant", "smoke-a", "manager")
            time.sleep(2)
            assert ask(url, bearer("smoke-a", "manager"), "Juniper")[1]["citations"][0]["source"] == source
            print("Container replacement, revocation and quarantined restore passed")
        except Exception:
            docker("logs", "--no-color", check=False)
            raise
        finally:
            docker("down", "--volumes", "--remove-orphans", check=False)


if __name__ == "__main__":
    main(sys.argv[1])
