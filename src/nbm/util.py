"""Shared paths, config loading and output helpers."""

from __future__ import annotations

import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

import yaml

ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = ROOT / "config"
DATA_RAW = ROOT / "data" / "raw"
DATA_PCAP = ROOT / "data" / "pcap"
OUTPUT_DIR = ROOT / "output"
DOCS_DIR = ROOT / "docs"
DETECTIONS_DIR = ROOT / "detections"

log = logging.getLogger("nbm")


def setup_logging(verbose: bool = False) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)-7s %(name)s: %(message)s",
    )


def load_env() -> dict[str, str]:
    """Read simple KEY=VALUE pairs from the gitignored .env, falling back to os.environ."""
    values: dict[str, str] = {}
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            values[key.strip()] = value.strip().strip('"').strip("'")
    for key in ("MTA_ZIP_PASSWORD",):
        if not values.get(key) and os.environ.get(key):
            values[key] = os.environ[key]
    return values


def load_cases(case_ids: Sequence[str] | None = None) -> list[dict[str, Any]]:
    """Load case definitions, optionally filtered to a subset of ids."""
    data = yaml.safe_load((CONFIG_DIR / "cases.yaml").read_text(encoding="utf-8"))
    cases = data.get("cases", [])
    if case_ids:
        wanted = set(case_ids)
        unknown = wanted - {c["id"] for c in cases}
        if unknown:
            raise SystemExit(f"unknown case id(s): {', '.join(sorted(unknown))}")
        cases = [c for c in cases if c["id"] in wanted]
    return cases


def case_output_dir(case_id: str) -> Path:
    path = OUTPUT_DIR / case_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def case_pcap_dir(case_id: str) -> Path:
    return DATA_PCAP / case_id


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: Sequence[str]) -> int:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(fieldnames), extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iso(ts: float) -> str:
    """Epoch seconds to an ISO-8601 UTC string with millisecond precision."""
    return (
        datetime.fromtimestamp(ts, tz=timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def human_duration(seconds: float) -> str:
    seconds = int(round(seconds))
    hours, rem = divmod(seconds, 3600)
    minutes, secs = divmod(rem, 60)
    if hours:
        return f"{hours}h{minutes:02d}m{secs:02d}s"
    if minutes:
        return f"{minutes}m{secs:02d}s"
    return f"{secs}s"


def is_private_ip(addr: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast


def defang(value: str) -> str:
    """Render a domain, URL or IP non-clickable for safe inclusion in reports."""
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )
