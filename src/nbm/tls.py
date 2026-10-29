"""TLS handshake parsing and client/server fingerprinting.

Implements JA3, JA3S, JA4 and JA4S directly from the ClientHello and ServerHello rather than
depending on a third-party library, so the exact field handling is visible and auditable.

JA3  = md5(version,ciphers,extensions,curves,point_formats)
JA4  = <proto><ver><sni><nciphers><nexts><alpn>_<sha256(sorted ciphers)[:12]>
       _<sha256(sorted extensions [+ "_" + sigalgs])[:12]>
JA3S = md5(version,cipher,extensions)
JA4S = <proto><ver><nexts><alpn>_<cipher>_<sha256(extensions in order)[:12]>

GREASE code points (RFC 8701) are stripped everywhere, since their whole purpose is to vary
between connections and including them would make the fingerprint unstable.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Any

from .pcapread import Capture
from .util import iso

CONTENT_HANDSHAKE = 0x16
HELLO_CLIENT = 0x01
HELLO_SERVER = 0x02

EXT_SNI = 0x0000
EXT_SUPPORTED_GROUPS = 0x000A
EXT_EC_POINT_FORMATS = 0x000B
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B

JA4_VERSIONS = {
    0x0304: "13",
    0x0303: "12",
    0x0302: "11",
    0x0301: "10",
    0x0300: "s3",
    0x0002: "s2",
}

VERSION_NAMES = {
    0x0304: "TLS 1.3",
    0x0303: "TLS 1.2",
    0x0302: "TLS 1.1",
    0x0301: "TLS 1.0",
    0x0300: "SSL 3.0",
}

EMPTY_HASH = "000000000000"


def is_grease(value: int) -> bool:
    """RFC 8701 GREASE values are 0x0a0a, 0x1a1a ... 0xfafa."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _sha12(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:12]


@dataclass
class ClientHello:
    legacy_version: int = 0
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    curves: list[int] = field(default_factory=list)
    point_formats: list[int] = field(default_factory=list)
    sig_algs: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)
    sni: str = ""


@dataclass
class ServerHello:
    legacy_version: int = 0
    cipher: int = 0
    extensions: list[int] = field(default_factory=list)
    supported_versions: list[int] = field(default_factory=list)
    alpn: list[str] = field(default_factory=list)


@dataclass
class TlsSession:
    ts: float
    client: str
    server: str
    sport: int
    dport: int
    sni: str = ""
    domain: str = ""
    version: str = ""
    alpn: str = ""
    ja3: str = ""
    ja3_string: str = ""
    ja4: str = ""
    server_ts: float | None = None
    server_version: str = ""
    cipher: str = ""
    ja3s: str = ""
    ja3s_string: str = ""
    ja4s: str = ""
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    duration: float = 0.0


class _Buf:
    """Bounds-checked sequential reader; any overrun aborts the parse."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def take(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ValueError("truncated")
        chunk = self.data[self.pos : self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return struct.unpack("!H", self.take(2))[0]

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos


def _u16_list(raw: bytes) -> list[int]:
    return [struct.unpack("!H", raw[i : i + 2])[0] for i in range(0, len(raw) - 1, 2)]


def _handshake_body(stream_data: bytes, want_type: int) -> bytes | None:
    """Pull one handshake message of the requested type out of the front of a TLS stream.

    A ClientHello can straddle several TLS records, so records are concatenated before the
    handshake header is read.
    """
    buf = _Buf(stream_data)
    payload = bytearray()
    try:
        while buf.remaining >= 5:
            content_type = buf.u8()
            buf.u16()  # record version, not used for fingerprinting
            length = buf.u16()
            if content_type != CONTENT_HANDSHAKE:
                return None
            payload.extend(buf.take(min(length, buf.remaining)))
            if len(payload) >= 4:
                declared = int.from_bytes(payload[1:4], "big")
                if len(payload) >= 4 + declared:
                    break
    except ValueError:
        pass

    if len(payload) < 4 or payload[0] != want_type:
        return None
    declared = int.from_bytes(payload[1:4], "big")
    body = bytes(payload[4 : 4 + declared])
    return body if len(body) >= 34 else None


def _parse_extensions(buf: _Buf, into: ClientHello | ServerHello) -> None:
    if buf.remaining < 2:
        return
    total = buf.u16()
    end = min(buf.pos + total, len(buf.data))
    while buf.pos + 4 <= end:
        ext_type = buf.u16()
        ext_len = buf.u16()
        if buf.pos + ext_len > end:
            return
        body = buf.take(ext_len)
        if not is_grease(ext_type):
            into.extensions.append(ext_type)

        try:
            if ext_type == EXT_SNI and isinstance(into, ClientHello):
                inner = _Buf(body)
                inner.u16()  # server name list length
                if inner.u8() == 0:  # host_name
                    into.sni = inner.take(inner.u16()).decode("utf-8", "replace").lower()
            elif ext_type == EXT_SUPPORTED_GROUPS:
                inner = _Buf(body)
                into.curves = [c for c in _u16_list(inner.take(inner.u16())) if not is_grease(c)]
            elif ext_type == EXT_EC_POINT_FORMATS and isinstance(into, ClientHello):
                inner = _Buf(body)
                into.point_formats = list(inner.take(inner.u8()))
            elif ext_type == EXT_SIGNATURE_ALGORITHMS and isinstance(into, ClientHello):
                inner = _Buf(body)
                into.sig_algs = [s for s in _u16_list(inner.take(inner.u16())) if not is_grease(s)]
            elif ext_type == EXT_SUPPORTED_VERSIONS:
                if isinstance(into, ClientHello):
                    inner = _Buf(body)
                    into.supported_versions = [
                        v for v in _u16_list(inner.take(inner.u8())) if not is_grease(v)
                    ]
                else:
                    into.supported_versions = [v for v in _u16_list(body) if not is_grease(v)]
            elif ext_type == EXT_ALPN:
                inner = _Buf(body)
                list_end = min(inner.pos + inner.u16(), len(body))
                while inner.pos < list_end:
                    into.alpn.append(inner.take(inner.u8()).decode("ascii", "replace"))
        except (ValueError, UnicodeDecodeError):
            continue


def parse_client_hello(stream_data: bytes) -> ClientHello | None:
    body = _handshake_body(stream_data, HELLO_CLIENT)
    if body is None:
        return None

    hello = ClientHello()
    buf = _Buf(body)
    try:
        hello.legacy_version = buf.u16()
        buf.take(32)  # random
        buf.take(buf.u8())  # session id
        hello.ciphers = [c for c in _u16_list(buf.take(buf.u16())) if not is_grease(c)]
        buf.take(buf.u8())  # compression methods
    except ValueError:
        return None

    _parse_extensions(buf, hello)
    return hello


def parse_server_hello(stream_data: bytes) -> ServerHello | None:
    body = _handshake_body(stream_data, HELLO_SERVER)
    if body is None:
        return None

    hello = ServerHello()
    buf = _Buf(body)
    try:
        hello.legacy_version = buf.u16()
        buf.take(32)  # random
        buf.take(buf.u8())  # session id
        hello.cipher = buf.u16()
        buf.u8()  # compression method
    except ValueError:
        return None

    _parse_extensions(buf, hello)
    return hello


def ja3(hello: ClientHello) -> tuple[str, str]:
    parts = [
        str(hello.legacy_version),
        "-".join(str(c) for c in hello.ciphers),
        "-".join(str(e) for e in hello.extensions),
        "-".join(str(c) for c in hello.curves),
        "-".join(str(p) for p in hello.point_formats),
    ]
    text = ",".join(parts)
    return hashlib.md5(text.encode()).hexdigest(), text


def ja3s(hello: ServerHello) -> tuple[str, str]:
    text = ",".join(
        [
            str(hello.legacy_version),
            str(hello.cipher),
            "-".join(str(e) for e in hello.extensions),
        ]
    )
    return hashlib.md5(text.encode()).hexdigest(), text


def _ja4_version(supported: list[int], legacy: int) -> str:
    best = max(supported) if supported else legacy
    return JA4_VERSIONS.get(best, "00")


def _ja4_alpn(alpn: list[str]) -> str:
    if not alpn or not alpn[0]:
        return "00"
    first = alpn[0]
    return f"{first[0]}{first[-1]}"


def ja4(hello: ClientHello) -> str:
    version = _ja4_version(hello.supported_versions, hello.legacy_version)
    sni_flag = "d" if hello.sni else "i"
    ja4_a = (
        f"t{version}{sni_flag}"
        f"{min(len(hello.ciphers), 99):02d}"
        f"{min(len(hello.extensions), 99):02d}"
        f"{_ja4_alpn(hello.alpn)}"
    )

    ciphers = sorted(f"{c:04x}" for c in hello.ciphers)
    ja4_b = _sha12(",".join(ciphers)) if ciphers else EMPTY_HASH

    # SNI and ALPN are counted in JA4_a but deliberately excluded from the extension hash so
    # the fingerprint tracks the client, not the destination it happens to be visiting.
    exts = sorted(
        f"{e:04x}" for e in hello.extensions if e not in (EXT_SNI, EXT_ALPN)
    )
    if exts:
        text = ",".join(exts)
        if hello.sig_algs:
            text += "_" + ",".join(f"{s:04x}" for s in hello.sig_algs)
        ja4_c = _sha12(text)
    else:
        ja4_c = EMPTY_HASH

    return f"{ja4_a}_{ja4_b}_{ja4_c}"


def ja4s(hello: ServerHello) -> str:
    version = _ja4_version(hello.supported_versions, hello.legacy_version)
    ja4s_a = f"t{version}{min(len(hello.extensions), 99):02d}{_ja4_alpn(hello.alpn)}"
    ja4s_b = f"{hello.cipher:04x}"
    # Server extensions are hashed in the order they appear, not sorted.
    exts = [f"{e:04x}" for e in hello.extensions]
    ja4s_c = _sha12(",".join(exts)) if exts else EMPTY_HASH
    return f"{ja4s_a}_{ja4s_b}_{ja4s_c}"


def extract_tls(capture: Capture, ip_to_domain: dict[str, list[str]]) -> list[TlsSession]:
    sessions: list[TlsSession] = []

    for key, conv in capture.conversations.items():
        _proto, client, sport, server, dport = key
        if not conv.c2s.data[:1] or conv.c2s.data[0] != CONTENT_HANDSHAKE:
            continue

        hello = parse_client_hello(conv.c2s.data)
        if hello is None:
            continue

        names = ip_to_domain.get(server, [])
        session = TlsSession(
            ts=conv.c2s.time_at(0),
            client=client,
            server=server,
            sport=sport,
            dport=dport,
            sni=hello.sni,
            domain=hello.sni or (names[0] if names else ""),
            version=VERSION_NAMES.get(
                max(hello.supported_versions) if hello.supported_versions else hello.legacy_version,
                f"0x{hello.legacy_version:04x}",
            ),
            alpn=",".join(hello.alpn),
        )
        session.ja3, session.ja3_string = ja3(hello)
        session.ja4 = ja4(hello)

        flow = capture.flows.get(key)
        if flow is not None:
            session.bytes_c2s = flow.bytes_c2s
            session.bytes_s2c = flow.bytes_s2c
            session.duration = flow.duration

        server_hello = parse_server_hello(conv.s2c.data)
        if server_hello is not None:
            session.server_ts = conv.s2c.time_at(0)
            session.cipher = f"0x{server_hello.cipher:04x}"
            session.server_version = VERSION_NAMES.get(
                max(server_hello.supported_versions)
                if server_hello.supported_versions
                else server_hello.legacy_version,
                f"0x{server_hello.legacy_version:04x}",
            )
            session.ja3s, session.ja3s_string = ja3s(server_hello)
            session.ja4s = ja4s(server_hello)

        sessions.append(session)

    sessions.sort(key=lambda s: s.ts)
    return sessions


TLS_FIELDS = [
    "timestamp",
    "client",
    "server",
    "dport",
    "sni",
    "domain",
    "version",
    "alpn",
    "ja3",
    "ja4",
    "cipher",
    "ja3s",
    "ja4s",
    "bytes_c2s",
    "bytes_s2c",
    "duration_s",
    "ja3_string",
]


def tls_rows(sessions: list[TlsSession]) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": iso(s.ts),
            "client": s.client,
            "server": s.server,
            "dport": s.dport,
            "sni": s.sni,
            "domain": s.domain,
            "version": s.version,
            "alpn": s.alpn,
            "ja3": s.ja3,
            "ja4": s.ja4,
            "cipher": s.cipher,
            "ja3s": s.ja3s,
            "ja4s": s.ja4s,
            "bytes_c2s": s.bytes_c2s,
            "bytes_s2c": s.bytes_s2c,
            "duration_s": round(s.duration, 3),
            "ja3_string": s.ja3_string,
        }
        for s in sessions
    ]
