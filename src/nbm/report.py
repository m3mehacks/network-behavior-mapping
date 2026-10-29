"""Render a per-case markdown report from the artifacts written by the analyze stage."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any, Iterable, Sequence

from .util import DOCS_DIR, case_output_dir, defang, log, read_json

MAX_TIMELINE_ROWS = 45
MAX_TABLE_ROWS = 15


def _read_csv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def _table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    rows = [[str(c).replace("|", "\\|") for c in row] for row in rows]
    if not rows:
        return "_None observed._\n"
    out = ["| " + " | ".join(headers) + " |", "|" + "|".join(["---"] * len(headers)) + "|"]
    out += ["| " + " | ".join(row) + " |" for row in rows]
    return "\n".join(out) + "\n"


def _time_only(timestamp: str) -> str:
    return timestamp[11:19] if len(timestamp) > 19 else timestamp


def _case_report(case_id: str) -> str | None:
    out = case_output_dir(case_id)
    summary_path = out / "summary.json"
    if not summary_path.exists():
        log.warning("%s: no summary.json, run 'analyze' first", case_id)
        return None

    summary = read_json(summary_path)
    iocs = read_json(out / "iocs.json")
    timeline = _read_csv(out / "timeline.csv")
    beacons = _read_csv(out / "beacons.csv")
    tls = _read_csv(out / "tls.csv")
    http = _read_csv(out / "http.csv")

    counts = summary["counts"]
    lines: list[str] = []

    lines.append(f"# {case_id}")
    lines.append("")
    lines.append(f"**Family:** {summary.get('family') or 'unknown'}  ")
    lines.append(f"**Source:** {summary.get('post')}  ")
    lines.append(f"**Capture:** {', '.join(summary.get('captures', []))}  ")
    lines.append(
        f"**Window:** {summary.get('first_ts')} to {summary.get('last_ts')} "
        f"({summary.get('duration_s', 0) / 60:.0f} minutes)"
    )
    lines.append("")
    lines.append(summary.get("summary", ""))
    lines.append("")
    lines.append(
        f"Parsed {counts['packets']:,} packets into {counts['flows']:,} flows, yielding "
        f"{counts['dns']} DNS events, {counts['http']} HTTP transactions, {counts['tls']} TLS "
        f"handshakes and {counts['beacons']} beacon candidates."
    )
    lines.append("")

    # --- Beaconing ---------------------------------------------------------------------
    lines.append("## Beaconing cadence")
    lines.append("")
    if beacons:
        lines.append(
            _table(
                ["Score", "Destination", "Port", "Kind", "Check-ins", "Interval", "Jitter", "Cadence"],
                [
                    [
                        f"{b['score']} ({b['verdict']})",
                        defang(b["destination"]),
                        b["dport"],
                        b["kind"],
                        b["events"],
                        f"{float(b['median_interval_s']):.0f}s",
                        f"{b['jitter_pct']}%",
                        b["cadence_class"].split(" (")[0],
                    ]
                    for b in beacons[:MAX_TABLE_ROWS]
                ],
            )
        )
        top = beacons[0]
        interval = float(top["median_interval_s"])
        lines.append("")
        lines.append(
            f"The most regular channel is {defang(top['destination'])} on port {top['dport']}: "
            f"{top['events']} events at a median of {interval:.0f} seconds with "
            f"{top['jitter_pct']}% jitter, sustained over {top['span']}."
        )
        if interval < 10:
            # Transport padding is more regular than any C2, so say so rather than letting the
            # score imply command and control.
            c2_like = [b for b in beacons if float(b["median_interval_s"]) >= 10]
            lines.append("")
            lines.append(
                "That cadence is below ten seconds, which is the rhythm of transport keepalive "
                "or padding rather than a command and control check-in. Tor behaves this way, "
                "and it outranks genuine C2 on regularity alone."
            )
            if c2_like:
                best = c2_like[0]
                lines.append("")
                lines.append(
                    f"The highest-scoring channel in the check-in range is "
                    f"{defang(best['destination'])} on port {best['dport']}, "
                    f"{best['events']} events every "
                    f"{float(best['median_interval_s']):.0f} seconds at "
                    f"{best['jitter_pct']}% jitter."
                )
    else:
        lines.append(
            "_No channel met the scoring threshold. Either the capture is too short for a "
            "cadence to emerge, or the malware communicates only on demand._"
        )
    lines.append("")

    # --- DNS ---------------------------------------------------------------------------
    lines.append("## DNS and C2 domains")
    lines.append("")
    suspicious = summary.get("suspicious_domains", [])
    lines.append(
        _table(
            ["Domain", "Lookups", "First seen", "Resolved to", "Response"],
            [
                [
                    defang(d["domain"]),
                    d["lookups"],
                    _time_only(d["first_seen"]),
                    defang(", ".join(d["ips"])) or "-",
                    d["rcodes"] or "-",
                ]
                for d in suspicious[:MAX_TABLE_ROWS]
            ],
        )
    )
    if len(suspicious) > MAX_TABLE_ROWS:
        lines.append("")
        lines.append(f"_{len(suspicious) - MAX_TABLE_ROWS} further domains in `output/{case_id}/dns.csv`._")
    lines.append("")

    # --- HTTP --------------------------------------------------------------------------
    lines.append("## HTTP endpoints")
    lines.append("")
    interesting = [
        h for h in http if h["host"] and not h["host"].startswith(("www.microsoft", "www.msft"))
    ]
    lines.append(
        _table(
            ["Time", "Method", "Endpoint", "Status", "Response", "Body"],
            [
                [
                    _time_only(h["timestamp"]),
                    h["method"],
                    defang(f"{h['host']}{h['uri']}")[:70],
                    h["status"] or "-",
                    f"{h['resp_body_len']} B",
                    h["body_magic"] + (" (mismatch)" if h["magic_mismatch"] == "True" else "") or "-",
                ]
                for h in interesting[:MAX_TABLE_ROWS]
            ],
        )
    )
    unusual_uas = [u for u in iocs.get("user_agents", []) if u["unusual"]]
    if unusual_uas:
        lines.append("")
        lines.append("Unusual user agents:")
        lines.append("")
        for ua in unusual_uas[:5]:
            lines.append(f"- `{ua['user_agent']}` ({ua['requests']} requests)")
    lines.append("")

    # --- TLS ---------------------------------------------------------------------------
    lines.append("## TLS fingerprints")
    lines.append("")
    seen: set[tuple] = set()
    fp_rows = []
    for t in tls:
        key = (t["ja4"], t["sni"] or t["server"])
        if key in seen:
            continue
        seen.add(key)
        fp_rows.append(
            [
                defang(t["sni"] or t["server"]),
                t["dport"],
                t["version"],
                t["ja4"],
                t["ja4s"] or "-",
                t["ja3"][:16] + "...",
            ]
        )
    lines.append(_table(["Destination", "Port", "Version", "JA4", "JA4S", "JA3"], fp_rows[:MAX_TABLE_ROWS]))
    lines.append("")

    # --- Timeline ----------------------------------------------------------------------
    lines.append("## Timeline of observed activity")
    lines.append("")
    notable = [row for row in timeline if int(row["significance"]) >= 2]
    shown = notable[:MAX_TIMELINE_ROWS]
    lines.append(
        _table(
            ["Time", "Phase", "Source", "Destination", "Observation"],
            [
                [
                    _time_only(row["timestamp"]),
                    row["phase"],
                    row["source"],
                    defang(row["destination"])[:48],
                    row["detail"][:110],
                ]
                for row in shown
            ],
        )
    )
    if len(notable) > MAX_TIMELINE_ROWS:
        lines.append("")
        lines.append(
            f"_{len(notable) - MAX_TIMELINE_ROWS} further notable events in "
            f"`output/{case_id}/timeline.csv`._"
        )
    lines.append("")

    # --- Indicators --------------------------------------------------------------------
    lines.append("## Indicators")
    lines.append("")
    lines.append("Defanged. Machine-readable copies are in `output/" + case_id + "/iocs.json`.")
    lines.append("")
    if iocs.get("domains"):
        lines.append("**Domains**")
        lines.append("")
        for d in iocs["domains"][:MAX_TABLE_ROWS]:
            lines.append(f"- `{defang(d['domain'])}` -> {defang(', '.join(d['resolved_to']))}")
        lines.append("")
    if iocs.get("addresses"):
        lines.append("**Addresses**")
        lines.append("")
        for a in iocs["addresses"][:MAX_TABLE_ROWS]:
            ports = ", ".join(str(p) for p in a["ports"])
            lines.append(f"- `{defang(a['ip'])}` ports {ports} ({', '.join(a['context'])})")
        lines.append("")
    if iocs.get("payload_downloads"):
        lines.append("**Payload retrievals**")
        lines.append("")
        for p in iocs["payload_downloads"]:
            note = " - content type mismatch" if p["content_type_mismatch"] else ""
            lines.append(
                f"- `{defang(p['url'])}` - {p['bytes']} bytes, {p['magic']}, "
                f"declared `{p['declared_content_type'] or 'nothing'}`{note}"
            )
        lines.append("")

    # --- Validation --------------------------------------------------------------------
    xref = iocs.get("cross_reference", {})
    if xref.get("published_domains") or xref.get("published_ips"):
        lines.append("## Cross-check against the published IOC list")
        lines.append("")
        lines.append(
            "The capture ships with an analyst-written indicator list. Comparing it with what "
            "the parsers recovered independently is this project's accuracy control."
        )
        lines.append("")
        rows = []
        for kind in ("domains", "ips"):
            recall = xref.get(f"{kind}_recall")
            rows.append(
                [
                    kind,
                    xref.get(f"published_{kind}", 0),
                    len(xref.get(f"matched_{kind}", [])),
                    "-" if recall is None else f"{recall * 100:.0f}%",
                ]
            )
        lines.append(_table(["Indicator type", "Published", "Recovered", "Recall"], rows))
        missed = xref.get("published_only_domains", []) + xref.get("published_only_ips", [])
        if missed:
            lines.append("")
            lines.append(
                "Present in the published list but not recovered from the capture "
                "(these are typically file hashes, sandbox-only artifacts, or names listed "
                "as context rather than contacted):"
            )
            lines.append("")
            lines.append("`" + "`, `".join(defang(m) for m in missed[:20]) + "`")
        lines.append("")

    lines.append("## Detection opportunities")
    lines.append("")
    lines.append(
        "Rules generated from this case are in [../detections/](../detections/); the rationale "
        "for each is in [detection-opportunities.md](detection-opportunities.md)."
    )
    lines.append("")

    return "\n".join(lines)


def report_all(cases: Iterable[dict[str, Any]]) -> None:
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    for case in cases:
        text = _case_report(case["id"])
        if text is None:
            continue
        path = DOCS_DIR / f"case-{case['id']}.md"
        path.write_text(text, encoding="utf-8")
        log.info("wrote %s", path.relative_to(path.parents[1]))
