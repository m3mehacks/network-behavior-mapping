"""DNS extraction: queries, answers and the domain-to-IP map used to attribute later traffic.

Named dnsx rather than dns so it can never shadow a stdlib or third-party `dns` module.
"""

from __future__ import annotations

import socket
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

import dpkt

from .pcapread import Capture
from .util import is_private_ip, iso

# Suffixes belonging to OS and browser background noise, excluded when ranking suspicious
# lookups so the interesting domains are not buried.
BENIGN_SUFFIXES = (
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "msftncsi.com",
    "msftconnecttest.com",
    "office.com",
    "office.net",
    "live.com",
    "bing.com",
    "google.com",
    "gstatic.com",
    "googleapis.com",
    "mozilla.com",
    "mozilla.net",
    "digicert.com",
    "verisign.com",
    "globalsign.com",
    "sectigo.com",
    "letsencrypt.org",
    "akamaiedge.net",
    "akamai.net",
    "in-addr.arpa",
    "ip6.arpa",
    "local",
)

# Hosts under otherwise-unremarkable providers that are routinely abused to stage payloads.
# Without this carve-out the benign-suffix filter hides exactly the traffic worth seeing;
# the Latrodectus capture in this dataset pulls from firebasestorage.googleapis.com.
ABUSED_HOSTS = (
    "firebasestorage.googleapis.com",
    "storage.googleapis.com",
    "drive.google.com",
    "docs.google.com",
    "script.google.com",
    "sites.google.com",
)

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
RTYPES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 65: "HTTPS"}


@dataclass
class DnsEvent:
    ts: float
    client: str
    server: str
    query: str
    qtype: str
    rcode: str = ""
    answers: list[str] = field(default_factory=list)
    cnames: list[str] = field(default_factory=list)
    response_ts: float | None = None

    @property
    def latency(self) -> float | None:
        return None if self.response_ts is None else self.response_ts - self.ts


def is_benign_domain(name: str) -> bool:
    name = name.lower().rstrip(".")
    if any(name == h or name.endswith("." + h) for h in ABUSED_HOSTS):
        return False
    return any(name == s or name.endswith("." + s) for s in BENIGN_SUFFIXES)


def _name(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace").rstrip(".").lower()
    return str(value).rstrip(".").lower()


def extract_dns(capture: Capture) -> tuple[list[DnsEvent], dict[str, list[str]]]:
    """Return DNS events (queries joined to their responses) and an IP-to-domain map."""
    pending: dict[tuple, DnsEvent] = {}
    events: list[DnsEvent] = []

    for ts, src, dst, sport, _dport, msg in capture.dns_messages:
        if not msg.qd:
            continue
        question = msg.qd[0]
        qname = _name(question.name)
        qtype = RTYPES.get(question.type, str(question.type))

        if msg.qr == dpkt.dns.DNS_Q:
            event = DnsEvent(ts=ts, client=src, server=dst, query=qname, qtype=qtype)
            events.append(event)
            pending[(msg.id, qname, question.type)] = event
            continue

        event = pending.pop((msg.id, qname, question.type), None)
        if event is None:
            # Response without a captured query still tells us where a name resolved to.
            event = DnsEvent(ts=ts, client=dst, server=src, query=qname, qtype=qtype)
            events.append(event)

        event.response_ts = ts
        event.rcode = RCODES.get(msg.rcode, str(msg.rcode))
        for rr in msg.an:
            if rr.type == dpkt.dns.DNS_A:
                event.answers.append(socket.inet_ntop(socket.AF_INET, rr.ip))
            elif rr.type == dpkt.dns.DNS_AAAA:
                event.answers.append(socket.inet_ntop(socket.AF_INET6, rr.ip6))
            elif rr.type == dpkt.dns.DNS_CNAME:
                event.cnames.append(_name(rr.cname))

    events.sort(key=lambda e: e.ts)

    ip_to_domain: dict[str, list[str]] = defaultdict(list)
    for event in events:
        for ip in event.answers:
            if event.query not in ip_to_domain[ip]:
                ip_to_domain[ip].append(event.query)

    return events, dict(ip_to_domain)


def dns_rows(events: list[DnsEvent]) -> list[dict[str, Any]]:
    rows = []
    for e in events:
        rows.append(
            {
                "timestamp": iso(e.ts),
                "client": e.client,
                "server": e.server,
                "query": e.query,
                "qtype": e.qtype,
                "rcode": e.rcode,
                "answers": ";".join(e.answers),
                "cnames": ";".join(e.cnames),
                "latency_ms": "" if e.latency is None else f"{e.latency * 1000:.1f}",
                "benign_suffix": is_benign_domain(e.query),
            }
        )
    return rows


DNS_FIELDS = [
    "timestamp",
    "client",
    "server",
    "query",
    "qtype",
    "rcode",
    "answers",
    "cnames",
    "latency_ms",
    "benign_suffix",
]


def suspicious_domains(events: list[DnsEvent]) -> list[dict[str, Any]]:
    """Domains worth attention: non-benign, resolved to a routable address."""
    grouped: dict[str, dict[str, Any]] = {}
    for e in events:
        if is_benign_domain(e.query):
            continue
        entry = grouped.setdefault(
            e.query,
            {"domain": e.query, "lookups": 0, "first_ts": e.ts, "last_ts": e.ts, "ips": [], "rcodes": set()},
        )
        entry["lookups"] += 1
        entry["first_ts"] = min(entry["first_ts"], e.ts)
        entry["last_ts"] = max(entry["last_ts"], e.ts)
        if e.rcode:
            entry["rcodes"].add(e.rcode)
        for ip in e.answers:
            if ip not in entry["ips"] and not is_private_ip(ip):
                entry["ips"].append(ip)

    for entry in grouped.values():
        entry["rcodes"] = ";".join(sorted(entry["rcodes"]))
    return sorted(grouped.values(), key=lambda d: d["first_ts"])
