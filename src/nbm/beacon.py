"""Beacon detection: find destinations contacted on a regular cadence.

Two kinds of channel are scored, because malware beacons in both shapes:

  connection  - a fresh TCP connection per check-in, timed from flow start times
  http        - repeated requests to one host, timed from request timestamps, which catches
                check-ins multiplexed over a single keep-alive connection
  keepalive   - periodic client-to-server packets inside one long-lived socket, which is how
                RATs such as Remcos and NetSupport hold a session open; without this a RAT
                looks like a single connection and shows no cadence at all

Regularity is measured with the median absolute deviation rather than the standard deviation.
MAD is resistant to outliers, so one long pause (the analyst stepping away, a retry after a
failed connection) does not hide an otherwise metronomic pattern the way a variance-based
measure would.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from .pcapread import Capture
from .util import human_duration, is_private_ip, iso

# Connections opened within this many seconds of each other are one check-in. Browsers and
# malware alike open several parallel sockets per contact; without collapsing them the
# interval series is dominated by near-zero deltas.
DEBOUNCE_S = 1.0

# A channel needs this many check-ins before a cadence claim is meaningful.
MIN_EVENTS = 5

# Sub-second cadences are streaming or transfer behaviour, not check-ins.
MIN_INTERVAL_S = 1.0
MAX_INTERVAL_S = 24 * 3600

SCORE_THRESHOLD = 55.0

# A socket must stay open at least this long before its internal packet rhythm is treated as
# a keepalive cadence rather than an ordinary transfer.
MIN_KEEPALIVE_DURATION_S = 120.0


@dataclass
class Beacon:
    kind: str
    client: str
    server: str
    dport: int
    label: str
    events: int
    first_ts: float
    last_ts: float
    median_interval: float
    mean_interval: float
    jitter_pct: float
    interval_cv: float
    size_mean: float
    size_cv: float
    score: float
    timestamps: list[float] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.last_ts - self.first_ts

    @property
    def verdict(self) -> str:
        if self.score >= 80:
            return "strong"
        if self.score >= SCORE_THRESHOLD:
            return "likely"
        return "weak"

    @property
    def destination(self) -> str:
        return self.label or self.server

    @property
    def cadence_class(self) -> str:
        """Separate transport-level rhythm from actual command and control check-ins.

        Score alone conflates them: Tor padding on tcp/9001 is more regular than any RAT,
        and would otherwise outrank a genuine 30-second Remcos heartbeat.
        """
        if self.median_interval < 10:
            return "sub-10s (transport keepalive or padding)"
        if self.median_interval <= 300:
            return "10-300s (typical C2 check-in)"
        if self.median_interval <= 3600:
            return "5-60min (low and slow C2)"
        return ">1h (very low and slow)"


def _debounce(events: list[tuple[float, int]]) -> list[tuple[float, int]]:
    """Collapse events that fall within DEBOUNCE_S, summing their byte counts."""
    if not events:
        return []
    events = sorted(events)
    merged = [list(events[0])]
    for ts, size in events[1:]:
        if ts - merged[-1][0] <= DEBOUNCE_S:
            merged[-1][1] += size
        else:
            merged.append([ts, size])
    return [(ts, size) for ts, size in merged]


def _cv(values: list[float]) -> float:
    """Coefficient of variation; 0 means perfectly uniform."""
    if len(values) < 2:
        return 0.0
    mean = statistics.fmean(values)
    if mean == 0:
        return 0.0
    return statistics.pstdev(values) / mean


def _score(jitter_ratio: float, events: int, size_cv: float) -> float:
    """Blend regularity, repetition and payload uniformity into a 0-100 confidence.

    Regularity dominates because it is the defining property of a beacon; repetition guards
    against calling three coincidentally-spaced connections a pattern; payload uniformity
    separates scripted check-ins from human-driven traffic of varying size.
    """
    regularity = max(0.0, 1.0 - min(jitter_ratio, 1.0))
    repetition = min(1.0, events / 20.0)
    uniformity = max(0.0, 1.0 - min(size_cv, 1.0))
    return round(100 * (0.55 * regularity + 0.30 * repetition + 0.15 * uniformity), 1)


def _analyse(kind: str, client: str, server: str, dport: int, label: str,
             raw_events: list[tuple[float, int]]) -> Beacon | None:
    events = _debounce(raw_events)
    if len(events) < MIN_EVENTS:
        return None

    times = [ts for ts, _ in events]
    sizes = [float(size) for _, size in events]
    intervals = [b - a for a, b in zip(times, times[1:])]
    if not intervals:
        return None

    median = statistics.median(intervals)
    if not (MIN_INTERVAL_S <= median <= MAX_INTERVAL_S):
        return None

    mad = statistics.median([abs(i - median) for i in intervals])
    jitter_ratio = mad / median if median else 1.0
    size_cv = _cv(sizes)

    return Beacon(
        kind=kind,
        client=client,
        server=server,
        dport=dport,
        label=label,
        events=len(events),
        first_ts=times[0],
        last_ts=times[-1],
        median_interval=median,
        mean_interval=statistics.fmean(intervals),
        jitter_pct=round(jitter_ratio * 100, 1),
        interval_cv=round(_cv(intervals), 3),
        size_mean=round(statistics.fmean(sizes), 1),
        size_cv=round(size_cv, 3),
        score=_score(jitter_ratio, len(events), size_cv),
        timestamps=times,
    )


def score_beacons(
    capture: Capture,
    ip_to_domain: dict[str, list[str]],
    http_txns: list,
    tls_sessions: list,
) -> list[Beacon]:
    """Rank every candidate beacon channel in a capture, highest confidence first."""
    sni_by_server: dict[str, str] = {}
    for session in tls_sessions:
        if session.sni:
            sni_by_server.setdefault(session.server, session.sni)

    def label_for(server: str) -> str:
        if server in sni_by_server:
            return sni_by_server[server]
        names = ip_to_domain.get(server, [])
        return names[0] if names else ""

    # Channel 1: one connection per check-in.
    by_dest: dict[tuple, list[tuple[float, int]]] = {}
    for flow in capture.flows.values():
        if is_private_ip(flow.dst):
            continue
        by_dest.setdefault((flow.src, flow.dst, flow.dport), []).append(
            (flow.first_ts, flow.bytes_c2s)
        )

    beacons: list[Beacon] = []
    for (client, server, dport), events in by_dest.items():
        beacon = _analyse("connection", client, server, dport, label_for(server), events)
        if beacon:
            beacons.append(beacon)

    # Channel 2: repeated HTTP requests, which survive connection reuse.
    by_host: dict[tuple, list[tuple[float, int]]] = {}
    for txn in http_txns:
        if is_private_ip(txn.server):
            continue
        host = txn.host or txn.server
        by_host.setdefault((txn.client, txn.server, txn.dport, host), []).append(
            (txn.ts, txn.req_body_len + len(txn.uri))
        )

    for (client, server, dport, host), events in by_host.items():
        beacon = _analyse("http", client, server, dport, host, events)
        if beacon:
            beacons.append(beacon)

    # Channel 3: heartbeat traffic inside a single long-lived socket.
    for flow in capture.flows.values():
        if flow.proto != "tcp" or is_private_ip(flow.dst):
            continue
        if flow.duration < MIN_KEEPALIVE_DURATION_S:
            continue
        beacon = _analyse(
            "keepalive",
            flow.src,
            flow.dst,
            flow.dport,
            label_for(flow.dst),
            flow.c2s_data_packets,
        )
        if beacon:
            beacons.append(beacon)

    beacons.sort(key=lambda b: b.score, reverse=True)
    return beacons


BEACON_FIELDS = [
    "score",
    "verdict",
    "cadence_class",
    "kind",
    "client",
    "server",
    "dport",
    "destination",
    "events",
    "first_seen",
    "last_seen",
    "span",
    "median_interval_s",
    "mean_interval_s",
    "jitter_pct",
    "interval_cv",
    "size_mean_bytes",
    "size_cv",
]


def beacon_rows(beacons: list[Beacon]) -> list[dict[str, Any]]:
    return [
        {
            "score": b.score,
            "verdict": b.verdict,
            "cadence_class": b.cadence_class,
            "kind": b.kind,
            "client": b.client,
            "server": b.server,
            "dport": b.dport,
            "destination": b.destination,
            "events": b.events,
            "first_seen": iso(b.first_ts),
            "last_seen": iso(b.last_ts),
            "span": human_duration(b.duration),
            "median_interval_s": round(b.median_interval, 2),
            "mean_interval_s": round(b.mean_interval, 2),
            "jitter_pct": b.jitter_pct,
            "interval_cv": b.interval_cv,
            "size_mean_bytes": b.size_mean,
            "size_cv": b.size_cv,
        }
        for b in beacons
    ]
