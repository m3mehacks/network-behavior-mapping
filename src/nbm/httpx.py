"""HTTP extraction from reassembled TCP streams.

Named httpx rather than http so it can never shadow the stdlib `http` package.

Messages are split by hand rather than with dpkt.http so that each one keeps its byte offset,
which is what lets a transaction be mapped back to the moment it appeared on the wire. The
first bytes of every response body are also sniffed, because a payload whose magic bytes
disagree with its declared Content-Type is one of the strongest signals in this traffic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterator

from .pcapread import Capture, Stream
from .util import iso

METHODS = (
    b"GET",
    b"POST",
    b"HEAD",
    b"PUT",
    b"DELETE",
    b"OPTIONS",
    b"CONNECT",
    b"TRACE",
    b"PATCH",
    b"PROPFIND",
    b"PROPPATCH",
    b"MKCOL",
    b"COPY",
    b"MOVE",
    b"LOCK",
    b"UNLOCK",
    b"SEARCH",
)

REQUEST_LINE = re.compile(rb"^(" + b"|".join(METHODS) + rb") (\S+) (HTTP/\d\.\d)$")
STATUS_LINE = re.compile(rb"^(HTTP/\d\.\d) (\d{3})(?: (.*))?$")

# Magic bytes worth flagging when they appear at the start of a response body.
MAGIC = [
    (b"MZ", "pe-executable"),
    (b"\x7fELF", "elf-executable"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf\x27\x1c", "7zip"),
    (b"%PDF", "pdf"),
    (b"\xd0\xcf\x11\xe0", "ole-compound"),
    (b"\x1f\x8b", "gzip"),
    (b"GIF8", "gif"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"<!DOCTYPE", "html"),
    (b"<html", "html"),
    (b"<?xml", "xml"),
    (b"{", "json-or-text"),
]

EXECUTABLE_MAGIC = {"pe-executable", "elf-executable"}


@dataclass
class HttpTransaction:
    ts: float
    client: str
    server: str
    sport: int
    dport: int
    method: str = ""
    host: str = ""
    uri: str = ""
    version: str = ""
    user_agent: str = ""
    referer: str = ""
    req_content_type: str = ""
    req_body_len: int = 0
    status: str = ""
    reason: str = ""
    resp_ts: float | None = None
    resp_content_type: str = ""
    resp_server: str = ""
    resp_body_len: int = 0
    body_magic: str = ""
    req_headers: dict[str, str] = field(default_factory=dict)

    @property
    def url(self) -> str:
        return f"http://{self.host}{self.uri}" if self.host else self.uri

    @property
    def magic_mismatch(self) -> bool:
        """Declared content type disagrees with what the body actually is."""
        if self.body_magic not in EXECUTABLE_MAGIC:
            return False
        declared = self.resp_content_type.lower()
        return not any(
            token in declared
            for token in ("application/x-msdownload", "application/octet-stream", "application/x-dosexec")
        )


def _decode(value: bytes) -> str:
    return value.decode("utf-8", "replace").strip()


def _parse_headers(block: bytes) -> tuple[bytes, dict[str, str]]:
    lines = block.split(b"\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, _, value = line.partition(b":")
        headers[_decode(name).lower()] = _decode(value)
    return lines[0], headers


def _body_length(headers: dict[str, str], remaining: int, is_response: bool) -> int:
    if "content-length" in headers:
        try:
            return min(int(headers["content-length"]), remaining)
        except ValueError:
            pass
    if headers.get("transfer-encoding", "").lower().startswith("chunked"):
        # Chunked bodies are not de-chunked here; consume the rest of the stream.
        return remaining
    return remaining if is_response else 0


def _iter_messages(data: bytes, is_response: bool) -> Iterator[tuple[int, bytes, dict[str, str], bytes]]:
    """Yield (offset, first_line, headers, body) for each HTTP message in a stream."""
    pos = 0
    pattern = STATUS_LINE if is_response else REQUEST_LINE
    while pos < len(data):
        end = data.find(b"\r\n\r\n", pos)
        if end == -1:
            return
        block = data[pos:end]
        first_line, headers = _parse_headers(block)
        if not pattern.match(first_line):
            # Not a message boundary after all; resynchronise past this header block.
            pos = end + 4
            continue

        body_start = end + 4
        body_len = _body_length(headers, len(data) - body_start, is_response)
        yield pos, first_line, headers, data[body_start : body_start + body_len]
        pos = body_start + body_len


def _sniff(body: bytes) -> str:
    head = body[:16]
    for magic, label in MAGIC:
        if head.startswith(magic):
            return label
    return ""


def _requests(stream: Stream, client: str, server: str, sport: int, dport: int) -> list[HttpTransaction]:
    out: list[HttpTransaction] = []
    for offset, line, headers, body in _iter_messages(stream.data, is_response=False):
        match = REQUEST_LINE.match(line)
        if not match:
            continue
        method, uri, version = (_decode(g) for g in match.groups())
        out.append(
            HttpTransaction(
                ts=stream.time_at(offset),
                client=client,
                server=server,
                sport=sport,
                dport=dport,
                method=method,
                uri=uri,
                version=version,
                host=headers.get("host", ""),
                user_agent=headers.get("user-agent", ""),
                referer=headers.get("referer", ""),
                req_content_type=headers.get("content-type", ""),
                req_body_len=len(body),
                req_headers=headers,
            )
        )
    return out


def extract_http(capture: Capture) -> list[HttpTransaction]:
    """Parse every HTTP transaction in the capture, pairing requests with their responses."""
    transactions: list[HttpTransaction] = []

    for key, conv in capture.conversations.items():
        _proto, client, sport, server, dport = key
        if b"HTTP/" not in conv.c2s.data[:4096] and b"HTTP/" not in conv.s2c.data[:4096]:
            continue

        reqs = _requests(conv.c2s, client, server, sport, dport)
        if not reqs:
            continue

        responses = list(_iter_messages(conv.s2c.data, is_response=True))
        for req, (offset, line, headers, body) in zip(reqs, responses):
            match = STATUS_LINE.match(line)
            if match:
                req.status = _decode(match.group(2))
                req.reason = _decode(match.group(3) or b"")
            req.resp_ts = conv.s2c.time_at(offset)
            req.resp_content_type = headers.get("content-type", "")
            req.resp_server = headers.get("server", "")
            req.resp_body_len = len(body)
            req.body_magic = _sniff(body)

        transactions.extend(reqs)

    transactions.sort(key=lambda t: t.ts)
    return transactions


HTTP_FIELDS = [
    "timestamp",
    "client",
    "server",
    "dport",
    "method",
    "host",
    "uri",
    "user_agent",
    "referer",
    "status",
    "req_content_type",
    "req_body_len",
    "resp_content_type",
    "resp_body_len",
    "body_magic",
    "magic_mismatch",
    "resp_server",
]


def http_rows(transactions: list[HttpTransaction]) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": iso(t.ts),
            "client": t.client,
            "server": t.server,
            "dport": t.dport,
            "method": t.method,
            "host": t.host,
            "uri": t.uri,
            "user_agent": t.user_agent,
            "referer": t.referer,
            "status": t.status,
            "req_content_type": t.req_content_type,
            "req_body_len": t.req_body_len,
            "resp_content_type": t.resp_content_type,
            "resp_body_len": t.resp_body_len,
            "body_magic": t.body_magic,
            "magic_mismatch": t.magic_mismatch,
            "resp_server": t.resp_server,
        }
        for t in transactions
    ]
