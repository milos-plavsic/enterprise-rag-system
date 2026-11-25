"""Ephemeral TLS JWKS fixture for the container smoke test only."""
import ssl
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer


if __name__ == "__main__":
    # nosec B104: disposable Compose fixture must accept connections from the isolated test network.\n    server = ThreadingHTTPServer(("0.0.0.0", 8443), partial(SimpleHTTPRequestHandler, directory="/fixture/keys"))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain("/fixture/cert.pem", "/fixture/idp.key")
    server.socket = tls.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
