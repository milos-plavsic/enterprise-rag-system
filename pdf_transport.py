"""Bounded PDF worker transport. The production API only speaks over a Unix socket."""
from __future__ import annotations

import json
import os
import socket
import struct
# Execute the fixed local parser worker, with untrusted bytes on stdin.
import subprocess  # nosec B404
import sys
from pathlib import Path
from threading import BoundedSemaphore
from time import monotonic

from pdf_worker import MAX_BYTES, MAX_CHARS, MAX_PAGES, MAX_WIRE, TIMEOUT

_parse_slots = BoundedSemaphore(2)


class ParserUnavailable(RuntimeError):
    pass


def isolated_parse(payload: bytes) -> bytes:
    if not payload or len(payload) > MAX_BYTES:
        return b""
    if not _parse_slots.acquire(blocking=False):
        raise ParserUnavailable("parser busy")
    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-I", str(Path(__file__).with_name("pdf_worker.py").resolve())],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=TIMEOUT,
            cwd=Path(__file__).resolve().parent,
            env={k: os.environ[k] for k in ("SYSTEMROOT", "WINDIR") if k in os.environ},
        )
    except subprocess.TimeoutExpired:
        return b""
    finally:
        _parse_slots.release()
    return result.stdout if result.returncode == 0 and len(result.stdout) <= MAX_WIRE else b""


def receive(stream: socket.socket, length: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < length:
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("parser deadline reached")
        stream.settimeout(remaining)
        chunk = stream.recv(min(length - len(result), 65_536))
        if not chunk:
            raise ConnectionError("truncated parser frame")
        result.extend(chunk)
    return bytes(result)


def exchange(path: str, payload: bytes) -> bytes:
    deadline = monotonic() + TIMEOUT + 2
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.settimeout(2)
            stream.connect(path)
            stream.sendall(struct.pack("!I", len(payload)) + payload)
            length = struct.unpack("!I", receive(stream, 4, deadline))[0]
            if length > MAX_WIRE:
                raise ParserUnavailable("parser frame exceeds limit")
            return receive(stream, length, deadline)
    except OSError as exc:
        raise ParserUnavailable("parser unavailable") from exc


def parse_pdf(payload: bytes, socket_path: str | None = None) -> list[str]:
    wire = exchange(socket_path, payload) if socket_path else isolated_parse(payload)
    if not wire:
        raise ValueError("PDF rejected by parser")
    pages = json.loads(wire)
    if (not isinstance(pages, list) or not 1 <= len(pages) <= MAX_PAGES
            or any(not isinstance(page, str) for page in pages)
            or sum(map(len, pages)) > MAX_CHARS):
        raise ValueError("invalid parser response")
    return pages


def parser_ready(path: str) -> None:
    if exchange(path, b"") != b"ok":
        raise ParserUnavailable("unexpected parser readiness response")
