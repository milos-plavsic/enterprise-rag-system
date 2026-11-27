"""Verify the actual smoke IdP TLS policy using in-memory handshakes."""
import runpy
import ssl
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "smoke_idp.py"


@pytest.fixture
def server_context(tmp_path, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .sign(key, hashes.SHA256()))
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                          serialization.PrivateFormat.PKCS8,
                                          serialization.NoEncryption()))
    server = Mock()
    monkeypatch.setattr("http.server.ThreadingHTTPServer", Mock(return_value=server))
    original_load = ssl.SSLContext.load_cert_chain
    contexts = []

    def load(context, certfile, keyfile):
        assert (certfile, keyfile) == ("/fixture/cert.pem", "/fixture/idp.key")
        contexts.append(context)
        original_load(context, str(cert_path), str(key_path))

    monkeypatch.setattr(ssl.SSLContext, "load_cert_chain", load)
    monkeypatch.setattr(ssl.SSLContext, "wrap_socket", Mock(return_value=Mock()))
    runpy.run_path(str(SCRIPT), run_name="__main__")
    server.serve_forever.assert_called_once()
    assert len(contexts) == 1
    return contexts[0], cert_path


def handshake(server_context, client_context):
    incoming_server, outgoing_server = ssl.MemoryBIO(), ssl.MemoryBIO()
    incoming_client, outgoing_client = ssl.MemoryBIO(), ssl.MemoryBIO()
    server = server_context.wrap_bio(incoming_server, outgoing_server, server_side=True)
    client = client_context.wrap_bio(incoming_client, outgoing_client,
                                     server_hostname="localhost")
    done = set()
    for _ in range(100):
        for peer, outgoing, incoming in ((client, outgoing_client, incoming_server),
                                         (server, outgoing_server, incoming_client)):
            if peer not in done:
                try:
                    peer.do_handshake()
                    done.add(peer)
                except ssl.SSLWantReadError:
                    pass
            data = outgoing.read()
            if data:
                incoming.write(data)
        if len(done) == 2:
            return client.version(), server.version()
    pytest.fail("TLS handshake did not complete")


def test_explicit_minimum(server_context):
    context, _ = server_context
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2


@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_modern_tls_handshake(server_context, version):
    context, cert_path = server_context
    if version == ssl.TLSVersion.TLSv1_3 and not ssl.HAS_TLSv1_3:
        pytest.skip("OpenSSL has no TLS 1.3 support")
    client = ssl.create_default_context(cafile=str(cert_path))
    client.minimum_version = client.maximum_version = version
    expected = {ssl.TLSVersion.TLSv1_2: "TLSv1.2", ssl.TLSVersion.TLSv1_3: "TLSv1.3"}[version]
    assert handshake(context, client) == (expected, expected)


@pytest.mark.filterwarnings("ignore:ssl.TLSVersion.TLSv1.* is deprecated:DeprecationWarning")
@pytest.mark.parametrize("version", [ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1])
def test_legacy_tls_rejected(server_context, version):
    context, cert_path = server_context
    client = ssl.create_default_context(cafile=str(cert_path))
    client.minimum_version = client.maximum_version = version
    # Deliberately enable legacy client ciphers only for the negative test.
    client.set_ciphers("DEFAULT:@SECLEVEL=0")
    with pytest.raises(ssl.SSLError):
        handshake(context, client)
