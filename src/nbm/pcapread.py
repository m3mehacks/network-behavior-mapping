"""Single-pass capture reader: packet decode, flow table and TCP stream reassembly.

Every later stage works off the `Capture` this module produces, so a capture is only read
from disk once no matter how many signals are extracted from it.
"""

from __future__ import annotations

import bisect
import socket
from bisect import bisect_right
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import dpkt

from .util import log

# Per-direction reassembly cap. Request and response headers live at the start of a stream, so
# this is ample for protocol analysis while keeping large captures within memory.
MAX_STREAM_BYTES = 1 << 20

# A gap larger than this is treated as truncated capture rather than something to pad over.
MAX_GAP_FILL = 1 << 16

# Upper bound on per-flow packet timing samples retained for cadence analysis.
MAX_FLOW_SAMPLES = 20_000

SEQ_MOD = 1 << 32


@dataclass
class Packet:
    ts: float
    proto: str
    src: str
    dst: str
    sport: int
    dport: int
    length: int
    payload: bytes
    flags: int = 0
    seq: int = 0


@dataclass
class Flow:
    """One transport conversation, oriented client to server."""

    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    first_ts: float
    last_ts: float
    pkts_c2s: int = 0
    pkts_s2c: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    saw_syn: bool = False
    saw_synack: bool = False
    saw_rst: bool = False
    saw_fin: bool = False
    # (timestamp, payload size) for client-to-server packets that carry data. Pure ACKs are
    # skipped so that keepalive cadence inside a long-lived connection can be measured
    # without the noise of the acknowledgement stream.
    c2s_data_packets: list[tuple[float, int]] = field(default_factory=list)

    @property
    def key(self) -> tuple:
        return (self.proto, self.src, self.sport, self.dst, self.dport)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def completed_handshake(self) -> bool:
        return self.saw_syn and self.saw_synack


@dataclass
class Stream:
    """Reassembled TCP payload for one connection, in both directions."""

    buf: bytearray = field(default_factory=bytearray)
    base_seq: int | None = None
    # (offset, timestamp) pairs so a byte position can be mapped back to when it arrived.
    marks: list[tuple[int, float]] = field(default_factory=list)
    truncated: bool = False

    def add(self, seq: int, payload: bytes, ts: float) -> None:
        if not payload or self.truncated:
            return
        if self.base_seq is None:
            self.base_seq = seq
        offset = (seq - self.base_seq) % SEQ_MOD

        # A wildly out-of-range offset means the ISN guess was wrong (capture started
        # mid-connection); anchor on this segment instead.
        if offset > len(self.buf) + MAX_GAP_FILL:
            if not self.buf:
                self.base_seq = seq
                offset = 0
            else:
                self.truncated = True
                return

        end = offset + len(payload)
        if end > MAX_STREAM_BYTES:
            self.truncated = True
            return
        if offset > len(self.buf):
            self.buf.extend(b"\x00" * (offset - len(self.buf)))
        if end > len(self.buf):
            self.buf.extend(b"\x00" * (end - len(self.buf)))

        self.buf[offset:end] = payload
        if not self.marks or self.marks[-1][0] != offset:
            bisect.insort(self.marks, (offset, ts))

    def time_at(self, offset: int) -> float:
        """Timestamp of the segment covering a byte offset."""
        if not self.marks:
            return 0.0
        idx = bisect_right(self.marks, (offset, float("inf"))) - 1
        return self.marks[max(idx, 0)][1]

    @property
    def data(self) -> bytes:
        return bytes(self.buf)


@dataclass
class Conversation:
    c2s: Stream = field(default_factory=Stream)
    s2c: Stream = field(default_factory=Stream)


@dataclass
class Capture:
    path: Path
    first_ts: float = 0.0
    last_ts: float = 0.0
    packet_count: int = 0
    flows: dict[tuple, Flow] = field(default_factory=dict)
    conversations: dict[tuple, Conversation] = field(default_factory=dict)
    # (ts, src, dst, sport, dport, dns message)
    dns_messages: list[tuple] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts


def _reader(fh, path: Path):
    magic = fh.read(4)
    fh.seek(0)
    if magic == b"\x0a\x0d\x0d\x0a":
        return dpkt.pcapng.Reader(fh)
    return dpkt.pcap.Reader(fh)


def _ip_layer(buf: bytes, datalink: int):
    """Strip the link layer and return the IP packet, or None if it is not IP."""
    if datalink == dpkt.pcap.DLT_EN10MB:
        eth = dpkt.ethernet.Ethernet(buf)
        return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if datalink == dpkt.pcap.DLT_LINUX_SLL:
        sll = dpkt.sll.SLL(buf)
        return sll.data if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None
    if datalink in (dpkt.pcap.DLT_RAW, 101, 12):
        version = buf[0] >> 4
        if version == 4:
            return dpkt.ip.IP(buf)
        if version == 6:
            return dpkt.ip6.IP6(buf)
        return None
    # Unknown link type: try Ethernet, which covers almost every public capture.
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except dpkt.UnpackError:
        return None
    return eth.data if isinstance(eth.data, (dpkt.ip.IP, dpkt.ip6.IP6)) else None


def _addr(raw: bytes) -> str:
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw)


def iter_packets(path: Path) -> Iterator[Packet]:
    """Yield decoded TCP and UDP packets from a capture file."""
    with path.open("rb") as fh:
        reader = _reader(fh, path)
        try:
            datalink = reader.datalink()
        except Exception:  # noqa: BLE001 - pcapng readers vary
            datalink = dpkt.pcap.DLT_EN10MB

        for ts, buf in reader:
            try:
                ip = _ip_layer(bytes(buf), datalink)
            except (dpkt.UnpackError, IndexError, AttributeError):
                continue
            if ip is None:
                continue

            transport = ip.data
            if isinstance(transport, dpkt.tcp.TCP):
                proto, flags, seq = "tcp", transport.flags, int(transport.seq)
            elif isinstance(transport, dpkt.udp.UDP):
                proto, flags, seq = "udp", 0, 0
            else:
                continue

            try:
                src, dst = _addr(ip.src), _addr(ip.dst)
            except ValueError:
                continue

            yield Packet(
                ts=float(ts),
                proto=proto,
                src=src,
                dst=dst,
                sport=int(transport.sport),
                dport=int(transport.dport),
                length=len(buf),
                payload=bytes(transport.data),
                flags=flags,
                seq=seq,
            )


def _orient(pkt: Packet, forward: tuple, reverse: tuple) -> tuple:
    """Pick the client-to-server key for a newly seen conversation.

    A bare SYN identifies the client outright. Failing that (UDP, or a capture that starts
    mid-connection) the lower port number is assumed to be the server.
    """
    if pkt.proto == "tcp":
        syn = bool(pkt.flags & dpkt.tcp.TH_SYN)
        ack = bool(pkt.flags & dpkt.tcp.TH_ACK)
        if syn and not ack:
            return forward
        if syn and ack:
            return reverse
    return reverse if pkt.sport < pkt.dport else forward


def read_capture(path: Path) -> Capture:
    """Read a capture once, building the flow table, TCP streams and DNS message list."""
    capture = Capture(path=path)
    # Maps either direction's 5-tuple to the canonical client-to-server key.
    orientation: dict[tuple, tuple] = {}

    for pkt in iter_packets(path):
        capture.packet_count += 1
        if capture.first_ts == 0.0:
            capture.first_ts = pkt.ts
        capture.last_ts = pkt.ts

        forward = (pkt.proto, pkt.src, pkt.sport, pkt.dst, pkt.dport)
        reverse = (pkt.proto, pkt.dst, pkt.dport, pkt.src, pkt.sport)

        key = orientation.get(forward) or orientation.get(reverse)
        if key is None:
            key = _orient(pkt, forward, reverse)
            orientation[forward] = key
            orientation[reverse] = key

        outbound = key == forward
        flow = capture.flows.get(key)
        if flow is None:
            flow = Flow(
                proto=key[0],
                src=key[1],
                sport=key[2],
                dst=key[3],
                dport=key[4],
                first_ts=pkt.ts,
                last_ts=pkt.ts,
            )
            capture.flows[key] = flow

        flow.last_ts = pkt.ts
        if outbound:
            flow.pkts_c2s += 1
            flow.bytes_c2s += len(pkt.payload)
            if pkt.payload and len(flow.c2s_data_packets) < MAX_FLOW_SAMPLES:
                flow.c2s_data_packets.append((pkt.ts, len(pkt.payload)))
        else:
            flow.pkts_s2c += 1
            flow.bytes_s2c += len(pkt.payload)

        if pkt.proto == "tcp":
            syn = bool(pkt.flags & dpkt.tcp.TH_SYN)
            ack = bool(pkt.flags & dpkt.tcp.TH_ACK)
            if syn and not ack and outbound:
                flow.saw_syn = True
            if syn and ack and not outbound:
                flow.saw_synack = True
            if pkt.flags & dpkt.tcp.TH_RST:
                flow.saw_rst = True
            if pkt.flags & dpkt.tcp.TH_FIN:
                flow.saw_fin = True

            if pkt.payload:
                conv = capture.conversations.setdefault(key, Conversation())
                stream = conv.c2s if outbound else conv.s2c
                stream.add(pkt.seq, pkt.payload, pkt.ts)
        elif 53 in (pkt.sport, pkt.dport) and pkt.payload:
            try:
                msg = dpkt.dns.DNS(pkt.payload)
            except Exception:  # noqa: BLE001 - malformed DNS is common in infection traffic
                continue
            capture.dns_messages.append((pkt.ts, pkt.src, pkt.dst, pkt.sport, pkt.dport, msg))

    log.info(
        "%s: %d packets, %d flows, %.0fs of traffic",
        path.name,
        capture.packet_count,
        len(capture.flows),
        capture.duration,
    )
    return capture
