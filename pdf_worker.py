"""Single-PDF parser child. Bounds are applied before importing the PDF library."""
from __future__ import annotations

import io
import json
import os
import sys

MAX_BYTES = 2_000_000
MAX_PAGES = 50
MAX_CHARS = 250_000
MAX_WIRE = 2_000_000
TIMEOUT = 10


def main() -> int:
    if os.name == "posix":
        import resource
        for limit, value in ((resource.RLIMIT_CPU, 3), (resource.RLIMIT_AS, 256 * 1024 * 1024),
                             (resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 0)):
            resource.setrlimit(limit, (value, value))
    from pypdf import PdfReader
    payload = sys.stdin.buffer.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES or not payload.startswith(b"%PDF-"):
        return 1
    try:
        reader = PdfReader(io.BytesIO(payload), strict=True)
        if reader.is_encrypted or not 1 <= len(reader.pages) <= MAX_PAGES:
            return 1
        pages = []
        total = 0
        for page in reader.pages:
            text = page.extract_text() or ""
            total += len(text)
            if total > MAX_CHARS:
                return 1
            pages.append(text)
        encoded = json.dumps(pages, ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_WIRE:
            return 1
        sys.stdout.buffer.write(encoded)
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
