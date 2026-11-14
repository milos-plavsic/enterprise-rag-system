"""Unix socket worker, deployed without network, identity secrets or corpus mounts."""
from __future__ import annotations

import os
import socketserver
import stat
import struct
import sys
from pathlib import Path
from time import monotonic

from pdf_transport import isolated_parse, receive
from pdf_worker import MAX_BYTES


class ParseRequest(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            deadline = monotonic() + 2
            size = struct.unpack("!I", receive(self.request, 4, deadline))[0]
            if size > MAX_BYTES:
                return
            result = isolated_parse(receive(self.request, size, deadline)) if size else b"ok"
            self.request.settimeout(2)
            self.request.sendall(struct.pack("!I", len(result)) + result)
        except OSError:
            return


class ParseServer(socketserver.UnixStreamServer):
    request_queue_size = 4


def serve(path: Path) -> None:
    os.umask(0o077)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        pass
    else:
        if not stat.S_ISSOCK(mode):
            raise RuntimeError("parser path is not a socket")
        # An operator starts one daemon. Refuse to replace a live peer.
        from pdf_transport import ParserUnavailable, parser_ready
        try:
            parser_ready(str(path))
        except ParserUnavailable as exc:
            import errno
            if not isinstance(exc.__cause__, OSError) or exc.__cause__.errno != errno.ECONNREFUSED:
                raise
            path.unlink()
        else:
            raise RuntimeError("parser already listening")
    with ParseServer(str(path), ParseRequest) as server:
        server.serve_forever()


if __name__ == "__main__":
    serve(Path(sys.argv[1]))
