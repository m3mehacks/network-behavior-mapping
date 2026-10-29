"""Pipeline driver: read each capture once and write every derived artifact for a case."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from .beacon import BEACON_FIELDS, beacon_rows, score_beacons
from .dnsx import DNS_FIELDS, dns_rows, extract_dns, suspicious_domains
from .httpx import HTTP_FIELDS, extract_http, http_rows
from .iocs import collect_iocs
from .pcapread import read_capture
from .timeline import TIMELINE_FIELDS, build_timeline, timeline_rows
from .tls import TLS_FIELDS, extract_tls, tls_rows
from .util import case_output_dir, case_pcap_dir, iso, log, write_csv, write_json

FLOW_FIELDS = [
    "start",
    "end",
    "duration_s",
    "proto",
    "client",
    "sport",
    "server",
    "dport",
    "domain",
    "pkts_c2s",
    "pkts_s2c",
    "bytes_c2s",
    "bytes_s2c",
    "handshake",
    "reset",
]


def _flow_rows(capture, ip_to_domain: dict[str, list[str]]) -> list[dict[str, Any]]:
    rows = []
    for flow in sorted(capture.flows.values(), key=lambda f: f.first_ts):
        rows.append(
            {
                "start": iso(flow.first_ts),
                "end": iso(flow.last_ts),
                "duration_s": f"{flow.duration:.3f}",
                "proto": flow.proto,
                "client": flow.src,
                "sport": flow.sport,
                "server": flow.dst,
                "dport": flow.dport,
                "domain": ";".join(ip_to_domain.get(flow.dst, [])),
                "pkts_c2s": flow.pkts_c2s,
                "pkts_s2c": flow.pkts_s2c,
                "bytes_c2s": flow.bytes_c2s,
                "bytes_s2c": flow.bytes_s2c,
                "handshake": flow.completed_handshake,
                "reset": flow.saw_rst,
            }
        )
    return rows


def analyze_case(case: dict[str, Any]) -> dict[str, Any] | None:
    case_id = case["id"]
    pcap_dir = case_pcap_dir(case_id)
    pcaps = sorted(p for p in pcap_dir.glob("*.pcap*")) if pcap_dir.exists() else []
    if not pcaps:
        log.warning("%s: no capture found, run 'fetch' first", case_id)
        return None

    out = case_output_dir(case_id)
    summary: dict[str, Any] = {
        "case": case_id,
        "family": case.get("family", ""),
        "summary": case.get("summary", ""),
        "tags": case.get("tags", []),
        "post": case.get("post", ""),
        "captures": [p.name for p in pcaps],
    }

    # One case may ship more than one capture file; results are concatenated.
    all_dns, all_http, all_tls, all_flows, all_beacons = [], [], [], [], []
    flow_objects = []
    ip_to_domain: dict[str, list[str]] = {}
    first_ts, last_ts, packets = 0.0, 0.0, 0

    for pcap in pcaps:
        capture = read_capture(pcap)
        packets += capture.packet_count
        first_ts = capture.first_ts if not first_ts else min(first_ts, capture.first_ts)
        last_ts = max(last_ts, capture.last_ts)

        dns_events, mapping = extract_dns(capture)
        for ip, names in mapping.items():
            ip_to_domain.setdefault(ip, [])
            for name in names:
                if name not in ip_to_domain[ip]:
                    ip_to_domain[ip].append(name)

        http_txns = extract_http(capture)
        tls_sessions = extract_tls(capture, ip_to_domain)
        beacons = score_beacons(capture, ip_to_domain, http_txns, tls_sessions)

        all_dns.extend(dns_events)
        all_http.extend(http_txns)
        all_tls.extend(tls_sessions)
        all_beacons.extend(beacons)
        all_flows.extend(_flow_rows(capture, ip_to_domain))
        flow_objects.extend(capture.flows.values())

    all_dns.sort(key=lambda e: e.ts)
    all_http.sort(key=lambda t: t.ts)
    all_tls.sort(key=lambda s: s.ts)
    all_beacons.sort(key=lambda b: b.score, reverse=True)

    counts = {
        "packets": packets,
        "flows": len(all_flows),
        "dns": write_csv(out / "dns.csv", dns_rows(all_dns), DNS_FIELDS),
        "http": write_csv(out / "http.csv", http_rows(all_http), HTTP_FIELDS),
        "tls": write_csv(out / "tls.csv", tls_rows(all_tls), TLS_FIELDS),
        "beacons": write_csv(out / "beacons.csv", beacon_rows(all_beacons), BEACON_FIELDS),
    }
    write_csv(out / "flows.csv", all_flows, FLOW_FIELDS)

    timeline = build_timeline(
        all_dns, all_http, all_tls, all_beacons, ip_to_domain, flow_objects
    )
    counts["timeline"] = write_csv(out / "timeline.csv", timeline_rows(timeline), TIMELINE_FIELDS)

    iocs = collect_iocs(case, all_dns, all_http, all_tls, all_beacons, ip_to_domain)
    write_json(out / "iocs.json", iocs)

    summary.update(
        {
            "first_ts": iso(first_ts) if first_ts else "",
            "last_ts": iso(last_ts) if last_ts else "",
            "duration_s": round(last_ts - first_ts, 3) if first_ts else 0,
            "counts": counts,
            "suspicious_domains": suspicious_domains(all_dns),
            "ip_to_domain": ip_to_domain,
        }
    )
    # Timestamps in the suspicious-domain summary are epoch floats; render them for the report.
    for entry in summary["suspicious_domains"]:
        entry["first_seen"] = iso(entry.pop("first_ts"))
        entry["last_seen"] = iso(entry.pop("last_ts"))

    write_json(out / "summary.json", summary)
    log.info(
        "%s: %d dns, %d http, %d tls, %d beacon candidates",
        case_id,
        counts["dns"],
        counts["http"],
        counts["tls"],
        counts["beacons"],
    )
    return summary


def analyze_all(cases: Iterable[dict[str, Any]]) -> dict[str, Any]:
    return {c["id"]: analyze_case(c) for c in cases}
