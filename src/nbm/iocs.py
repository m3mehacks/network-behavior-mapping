"""Indicator extraction, plus a cross-check against the IOC list published with each capture.

The cross-check is the project's accuracy control. Each malware-traffic-analysis.net post ships
an analyst-written IOC list; comparing it with what the parsers found independently shows how
much of the ground truth the pipeline recovers, and surfaces anything it misses.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from .beacon import SCORE_THRESHOLD, Beacon
from .dnsx import DnsEvent, is_benign_domain
from .httpx import EXECUTABLE_MAGIC, HttpTransaction
from .tls import TlsSession
from .util import case_pcap_dir, is_private_ip, iso

IPV4 = re.compile(r"\b(?:\d{1,3}(?:\[\.\]|\.)){3}\d{1,3}\b")
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\[\.\]|\.)){1,}[a-z]{2,24}\b", re.I)

# IOC lists mix domains with filenames. Without this, entries like index.php and 203.png are
# counted as domains and the recall figure becomes meaningless.
FILE_EXTENSIONS = {
    "asp", "aspx", "bat", "bin", "cab", "cmd", "css", "dat", "dll", "doc", "docx", "exe",
    "gif", "hta", "htm", "html", "img", "ini", "iso", "jpeg", "jpg", "js", "jse", "json",
    "lnk", "log", "msi", "ocx", "pdf", "php", "png", "ps1", "psd", "py", "rar", "rtf", "scr",
    "svg", "sys", "tar", "tgz", "tmp", "txt", "vbe", "vbs", "wsf", "xls", "xlsx", "xml",
    "zip", "7z",
}

# User agents that are unremarkable on a Windows host; anything else is worth reporting.
COMMON_UA_TOKENS = ("mozilla/5.0", "mozilla/4.0")


def refang(value: str) -> str:
    return value.replace("[.]", ".").replace("[:]", ":").strip().lower().rstrip(".")


def _published_iocs(case_id: str) -> dict[str, set[str]]:
    """Parse domains and addresses out of the IOC text file shipped with the capture."""
    found: dict[str, set[str]] = {"domains": set(), "ips": set()}
    pcap_dir = case_pcap_dir(case_id)
    if not pcap_dir.exists():
        return found

    for path in pcap_dir.glob("*.txt"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for match in IPV4.findall(text):
            ip = refang(match)
            if not is_private_ip(ip):
                found["ips"].add(ip)
        for match in DOMAIN.findall(text):
            domain = refang(match)
            if IPV4.fullmatch(domain) or "." not in domain:
                continue
            tld = domain.rsplit(".", 1)[-1]
            if not tld.isalpha() or tld in FILE_EXTENSIONS or len(domain) <= 4:
                continue
            found["domains"].add(domain)
    return found


def collect_iocs(
    case: dict[str, Any],
    dns_events: list[DnsEvent],
    http_txns: list[HttpTransaction],
    tls_sessions: list[TlsSession],
    beacons: list[Beacon],
    ip_to_domain: dict[str, list[str]],
) -> dict[str, Any]:
    domains: dict[str, dict[str, Any]] = {}

    def note_domain(name: str, ts: float, resolved: list[str], source: str) -> None:
        if not name or is_benign_domain(name):
            return
        entry = domains.setdefault(
            name, {"domain": name, "first_seen": iso(ts), "resolved_to": [], "seen_in": []}
        )
        for ip in resolved:
            if ip not in entry["resolved_to"]:
                entry["resolved_to"].append(ip)
        if source not in entry["seen_in"]:
            entry["seen_in"].append(source)

    for e in dns_events:
        if e.answers:
            note_domain(e.query, e.ts, e.answers, "dns")

    # A name can be contacted without a captured lookup: the resolution may predate the
    # capture, be cached, or go out over DoH. TLS SNI and the HTTP Host header still name it.
    for s in tls_sessions:
        note_domain(s.sni, s.ts, [s.server] if s.server else [], "tls-sni")
    for t in http_txns:
        note_domain(t.host.split(":")[0], t.ts, [t.server] if t.server else [], "http-host")

    addresses: dict[str, dict[str, Any]] = {}

    def note_ip(ip: str, ts: float, port: int, context: str) -> None:
        if is_private_ip(ip):
            return
        entry = addresses.setdefault(
            ip,
            {
                "ip": ip,
                "first_seen": iso(ts),
                "ports": [],
                "domains": ip_to_domain.get(ip, []),
                "context": [],
            },
        )
        if port not in entry["ports"]:
            entry["ports"].append(port)
        if context not in entry["context"]:
            entry["context"].append(context)

    urls: list[dict[str, Any]] = []
    user_agents: dict[str, dict[str, Any]] = {}
    payload_downloads: list[dict[str, Any]] = []

    for t in http_txns:
        if is_benign_domain(t.host):
            continue
        note_ip(t.server, t.ts, t.dport, "http")
        urls.append(
            {
                "url": t.url,
                "method": t.method,
                "first_seen": iso(t.ts),
                "status": t.status,
                "resp_bytes": t.resp_body_len,
                "body_magic": t.body_magic,
            }
        )
        if t.user_agent:
            ua = user_agents.setdefault(
                t.user_agent,
                {
                    "user_agent": t.user_agent,
                    "hosts": [],
                    "requests": 0,
                    "unusual": not any(tok in t.user_agent.lower() for tok in COMMON_UA_TOKENS),
                },
            )
            ua["requests"] += 1
            if t.host and t.host not in ua["hosts"]:
                ua["hosts"].append(t.host)
        if t.body_magic in EXECUTABLE_MAGIC:
            payload_downloads.append(
                {
                    "url": t.url,
                    "timestamp": iso(t.ts),
                    "bytes": t.resp_body_len,
                    "magic": t.body_magic,
                    "declared_content_type": t.resp_content_type,
                    "content_type_mismatch": t.magic_mismatch,
                }
            )

    fingerprints: dict[str, dict[str, Any]] = {}
    for s in tls_sessions:
        if is_benign_domain(s.sni):
            continue
        note_ip(s.server, s.ts, s.dport, "tls")
        entry = fingerprints.setdefault(
            s.ja4,
            {"ja4": s.ja4, "ja3": s.ja3, "sessions": 0, "destinations": [], "ja4s": []},
        )
        entry["sessions"] += 1
        dest = s.sni or s.server
        if dest not in entry["destinations"]:
            entry["destinations"].append(dest)
        if s.ja4s and s.ja4s not in entry["ja4s"]:
            entry["ja4s"].append(s.ja4s)

    beacon_iocs = [
        {
            "destination": b.destination,
            "server": b.server,
            "port": b.dport,
            "median_interval_s": round(b.median_interval, 1),
            "jitter_pct": b.jitter_pct,
            "check_ins": b.events,
            "score": b.score,
            "verdict": b.verdict,
        }
        for b in beacons
        if b.score >= SCORE_THRESHOLD
    ]
    for b in beacons:
        if b.score >= SCORE_THRESHOLD:
            note_ip(b.server, b.first_ts, b.dport, "beacon")

    # Deduplicate URLs while preserving order of first appearance.
    seen_urls: set[str] = set()
    unique_urls = []
    for u in urls:
        if u["url"] in seen_urls:
            continue
        seen_urls.add(u["url"])
        unique_urls.append(u)

    published = _published_iocs(case["id"])
    observed_domains = set(domains) | {u["url"].split("/")[2].split(":")[0] for u in unique_urls if "//" in u["url"]}
    observed_ips = set(addresses)

    cross_reference = {
        "published_domains": len(published["domains"]),
        "published_ips": len(published["ips"]),
        "matched_domains": sorted(published["domains"] & observed_domains),
        "matched_ips": sorted(published["ips"] & observed_ips),
        "published_only_domains": sorted(published["domains"] - observed_domains),
        "published_only_ips": sorted(published["ips"] - observed_ips),
    }
    for kind in ("domains", "ips"):
        total = cross_reference[f"published_{kind}"]
        matched = len(cross_reference[f"matched_{kind}"])
        cross_reference[f"{kind}_recall"] = round(matched / total, 3) if total else None

    return {
        "case": case["id"],
        "family": case.get("family", ""),
        "domains": sorted(domains.values(), key=lambda d: d["first_seen"]),
        "addresses": sorted(addresses.values(), key=lambda a: a["first_seen"]),
        "urls": unique_urls,
        "user_agents": sorted(user_agents.values(), key=lambda u: -u["requests"]),
        "tls_fingerprints": sorted(fingerprints.values(), key=lambda f: -f["sessions"]),
        "payload_downloads": payload_downloads,
        "beacons": beacon_iocs,
        "cross_reference": cross_reference,
    }
