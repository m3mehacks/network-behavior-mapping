"""Merge every extracted signal into one phase-labelled chronology.

Phases are inferred from ordering and content rather than asserted: the first response whose
body carries executable magic bytes anchors payload delivery, anything to a scored beacon
destination is a check-in, and an outbound POST carrying substantially more data than it
receives is treated as exfiltration.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .beacon import SCORE_THRESHOLD, Beacon
from .dnsx import DnsEvent, is_benign_domain
from .httpx import EXECUTABLE_MAGIC, HttpTransaction
from .tls import TlsSession
from .util import iso

PHASE_DNS = "dns-resolution"
PHASE_ACCESS = "initial-access"
PHASE_DELIVERY = "payload-delivery"
PHASE_C2 = "c2-check-in"
PHASE_EXFIL = "exfiltration"
PHASE_POST = "post-infection"

# An outbound body above this size on a POST to a non-benign host reads as data leaving.
EXFIL_MIN_BODY = 1024

# An encrypted session that pulls down this much from a first-contact host is payload
# retrieval in all but name, even though the content itself cannot be inspected.
TLS_DELIVERY_MIN_BYTES = 100_000

# Ports where a long-lived connection does not need explaining.
COMMON_PORTS = {80, 443, 53, 8080, 8443, 123, 25, 587, 993, 995, 22}

# Ports on which a TLS handshake is expected. Anywhere else, TLS is being used to blend in.
TLS_PORTS = {443, 8443, 993, 995, 465, 587, 636, 989, 990}

# A raw connection held open this long to an unusual port is reported in its own right.
LONG_LIVED_S = 120.0

# Outbound volume on an undecoded flow that, when it dwarfs what came back, reads as exfil.
EXFIL_MIN_FLOW_BYTES = 256_000
EXFIL_RATIO = 4.0

# Significance drives what reaches the written report; everything still lands in the CSV.
SIG_NOISE = 0
SIG_CONTEXT = 1
SIG_NOTABLE = 2
SIG_KEY = 3


@dataclass
class TimelineEvent:
    ts: float
    phase: str
    kind: str
    source: str
    destination: str
    detail: str
    significance: int = SIG_CONTEXT


def _benign(host: str) -> bool:
    return bool(host) and is_benign_domain(host)


def build_timeline(
    dns_events: list[DnsEvent],
    http_txns: list[HttpTransaction],
    tls_sessions: list[TlsSession],
    beacons: list[Beacon],
    ip_to_domain: dict[str, list[str]],
    flows: list | None = None,
) -> list[TimelineEvent]:
    beacon_dests = {
        (b.server, b.dport) for b in beacons if b.score >= SCORE_THRESHOLD
    }

    # Payload retrieval anchors the phase split. It is visible either as executable magic in a
    # cleartext response or as a large download inside an otherwise unremarkable TLS session.
    delivery_candidates = [t.ts for t in http_txns if t.body_magic in EXECUTABLE_MAGIC]
    delivery_candidates += [
        s.ts
        for s in tls_sessions
        if s.bytes_s2c >= TLS_DELIVERY_MIN_BYTES and not _benign(s.sni)
    ]
    delivery_ts = min(delivery_candidates, default=None)

    events: list[TimelineEvent] = []

    for e in dns_events:
        benign = is_benign_domain(e.query)
        events.append(
            TimelineEvent(
                ts=e.ts,
                phase=PHASE_DNS,
                kind="dns",
                source=e.client,
                destination=e.query,
                detail=f"{e.qtype} query -> {e.rcode or 'no response'}"
                + (f" [{', '.join(e.answers)}]" if e.answers else ""),
                significance=SIG_NOISE if benign else SIG_NOTABLE,
            )
        )

    for t in http_txns:
        host = t.host or t.server
        benign = _benign(t.host)
        exfil = (
            t.method == "POST"
            and t.req_body_len >= EXFIL_MIN_BODY
            and t.req_body_len > t.resp_body_len
            and not benign
        )
        executable = t.body_magic in EXECUTABLE_MAGIC

        if executable:
            phase, significance = PHASE_DELIVERY, SIG_KEY
        elif exfil:
            phase, significance = PHASE_EXFIL, SIG_KEY
        elif (t.server, t.dport) in beacon_dests:
            phase, significance = PHASE_C2, SIG_NOTABLE
        elif benign:
            phase, significance = PHASE_POST, SIG_NOISE
        elif delivery_ts is not None and t.ts < delivery_ts:
            phase, significance = PHASE_ACCESS, SIG_NOTABLE
        else:
            phase, significance = PHASE_POST, SIG_CONTEXT

        detail = f"{t.method} {t.uri}"
        if t.status:
            detail += f" -> {t.status}"
        if t.resp_body_len:
            detail += f", {t.resp_body_len} bytes"
        if t.body_magic:
            detail += f", body={t.body_magic}"
        if t.magic_mismatch:
            detail += f" (declared {t.resp_content_type or 'nothing'})"
            significance = SIG_KEY
        if t.req_body_len:
            detail += f", sent {t.req_body_len} bytes"

        events.append(
            TimelineEvent(
                ts=t.ts,
                phase=phase,
                kind="http",
                # A Host header may already carry the port; do not append it twice.
                destination=host if ":" in host else f"{host}:{t.dport}",
                source=t.client,
                detail=detail,
                significance=significance,
            )
        )

    for s in tls_sessions:
        benign = _benign(s.sni)
        large_download = s.bytes_s2c >= TLS_DELIVERY_MIN_BYTES and not benign

        if large_download and (delivery_ts is not None and s.ts <= delivery_ts):
            phase, significance = PHASE_DELIVERY, SIG_KEY
        elif (s.server, s.dport) in beacon_dests:
            phase, significance = PHASE_C2, SIG_NOTABLE
        elif benign:
            phase, significance = PHASE_POST, SIG_NOISE
        elif large_download:
            phase, significance = PHASE_DELIVERY, SIG_KEY
        elif delivery_ts is not None and s.ts < delivery_ts:
            phase, significance = PHASE_ACCESS, SIG_NOTABLE
        else:
            phase, significance = PHASE_POST, SIG_CONTEXT

        # A TLS connection with no SNI to a raw address is unusual outside of malware.
        if not s.sni and not benign and significance < SIG_NOTABLE:
            significance = SIG_NOTABLE

        detail = f"{s.version} handshake, JA3 {s.ja3[:12]}..., JA4 {s.ja4}"
        if s.dport not in TLS_PORTS:
            detail += f", TLS on non-standard port {s.dport}"
            significance = max(significance, SIG_NOTABLE)
        if not s.sni:
            detail += ", no SNI"
        if s.bytes_s2c:
            detail += f", received {s.bytes_s2c} bytes"

        events.append(
            TimelineEvent(
                ts=s.ts,
                phase=phase,
                kind="tls",
                source=s.client,
                destination=f"{s.sni or s.server}:{s.dport}",
                detail=detail,
                significance=significance,
            )
        )

    # Raw flows matter when nothing above decoded them: a RAT holding a socket open on an
    # unusual port produces no DNS, HTTP or TLS event after the initial lookup.
    decoded = {(s.server, s.sport) for s in tls_sessions} | {
        (t.server, t.sport) for t in http_txns
    }
    for flow in flows or []:
        if flow.proto != "tcp" or (flow.dst, flow.sport) in decoded:
            continue
        names = ip_to_domain.get(flow.dst, [])
        host = names[0] if names else flow.dst
        if _benign(host):
            continue

        unusual_port = flow.dport not in COMMON_PORTS
        long_lived = flow.duration >= LONG_LIVED_S
        exfil = (
            flow.bytes_c2s >= EXFIL_MIN_FLOW_BYTES
            and flow.bytes_c2s > flow.bytes_s2c * EXFIL_RATIO
        )
        # Traffic on a TLS port that never presented a ClientHello is a protocol masquerade:
        # the port was chosen to pass egress filtering, not because TLS is in use.
        fake_tls = flow.dport in TLS_PORTS and flow.bytes_c2s > 0
        if not (unusual_port or long_lived or exfil or fake_tls):
            continue

        reasons = []
        if fake_tls:
            reasons.append(f"port {flow.dport} with no TLS handshake")
        if unusual_port:
            reasons.append("non-standard port")
        if long_lived:
            reasons.append(f"held open {flow.duration:.0f}s")
        if exfil:
            reasons.append("outbound volume dwarfs inbound")

        if exfil:
            phase, significance = PHASE_EXFIL, SIG_KEY
        elif (flow.dst, flow.dport) in beacon_dests:
            phase, significance = PHASE_C2, SIG_KEY
        elif fake_tls:
            phase, significance = PHASE_POST, SIG_KEY
        else:
            phase = PHASE_POST
            significance = SIG_KEY if (unusual_port and long_lived) else SIG_NOTABLE

        events.append(
            TimelineEvent(
                ts=flow.first_ts,
                phase=phase,
                kind="flow",
                source=flow.src,
                destination=f"{host}:{flow.dport}",
                detail=(
                    f"undecoded TCP session, {', '.join(reasons)}, "
                    f"{flow.bytes_c2s} bytes out / {flow.bytes_s2c} bytes in"
                ),
                significance=significance,
            )
        )

    for b in beacons:
        if b.score < SCORE_THRESHOLD:
            continue
        events.append(
            TimelineEvent(
                ts=b.first_ts,
                phase=PHASE_C2,
                kind="beacon",
                source=b.client,
                destination=f"{b.destination}:{b.dport}",
                detail=(
                    f"{b.events} {b.kind} check-ins every ~{b.median_interval:.0f}s "
                    f"(jitter {b.jitter_pct:.0f}%, score {b.score})"
                ),
                significance=SIG_KEY,
            )
        )

    events.sort(key=lambda e: (e.ts, e.kind))
    return events


TIMELINE_FIELDS = ["timestamp", "phase", "kind", "source", "destination", "detail", "significance"]


def timeline_rows(events: list[TimelineEvent]) -> list[dict[str, Any]]:
    return [
        {
            "timestamp": iso(e.ts),
            "phase": e.phase,
            "kind": e.kind,
            "source": e.source,
            "destination": e.destination,
            "detail": e.detail,
            "significance": e.significance,
        }
        for e in events
    ]


def key_events(events: list[TimelineEvent], limit: int = 40) -> list[TimelineEvent]:
    """The narrative spine of a case: notable events, deduplicated and capped."""
    seen: set[tuple] = set()
    picked: list[TimelineEvent] = []
    for e in sorted(events, key=lambda e: e.ts):
        if e.significance < SIG_NOTABLE:
            continue
        # Collapse repeated identical check-ins to the same destination.
        signature = (e.kind, e.phase, e.destination, e.detail.split(",")[0])
        if signature in seen and e.significance < SIG_KEY:
            continue
        seen.add(signature)
        picked.append(e)

    if len(picked) <= limit:
        return picked
    # Keep every key event, then fill remaining slots with the earliest notable ones.
    critical = [e for e in picked if e.significance >= SIG_KEY]
    rest = [e for e in picked if e.significance < SIG_KEY]
    keep = critical + rest[: max(0, limit - len(critical))]
    return sorted(keep, key=lambda e: e.ts)
