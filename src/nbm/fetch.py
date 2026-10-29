"""Download and extract capture files from malware-traffic-analysis.net posts.

The posts that host these captures also host live malware binaries, so every filename is
checked against both a denylist and an allowlist before anything is written to disk, and the
same check is applied again to the members inside each archive.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

import pyzipper
import requests

from .util import DATA_PCAP, DATA_RAW, load_env, log

USER_AGENT = "network-behavior-mapping/1.0 (research; passive pcap analysis)"

# Only capture files and their IOC text listings are ever fetched.
ALLOW = re.compile(r"(\.pcap\.zip|IOCs[^/]*\.txt\.zip)$", re.IGNORECASE)

# Rejected outright, even if something above were to match. The posts publish live samples as
# *-malware.zip alongside the captures, plus emails and script droppers.
DENY = re.compile(
    r"(malware|sample|\.exe|\.dll|\.eml|\.msi|\.js|\.jse|\.vbs|\.ps1|\.hta|\.lnk"
    r"|\.doc|\.docx|\.xls|\.xlsx|\.rtf|\.iso|\.img|\.7z|\.rar)",
    re.IGNORECASE,
)

# Members permitted out of an archive once it has been downloaded.
ALLOWED_MEMBER_SUFFIXES = {".pcap", ".pcapng", ".txt"}

POST_DATE = re.compile(r"/(\d{4})/(\d{2})/(\d{2})/")


def is_safe_filename(name: str) -> bool:
    return bool(ALLOW.search(name)) and not DENY.search(name)


def derive_password(post_url: str) -> str:
    """Archive passwords follow infected_YYYYMMDD, taken from the post date in the URL."""
    match = POST_DATE.search(urlparse(post_url).path)
    if not match:
        raise ValueError(f"cannot derive archive password, no date in post URL: {post_url}")
    return "infected_" + "".join(match.groups())


def _session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    return session


def scrape_post(session: requests.Session, post_url: str) -> list[tuple[str, str]]:
    """Return (filename, url) for every downloadable file on a post that passes the filter."""
    response = session.get(post_url, timeout=60)
    response.raise_for_status()

    seen: dict[str, str] = {}
    for href in re.findall(r'href="([^"]+)"', response.text):
        name = href.rsplit("/", 1)[-1]
        if is_safe_filename(name):
            seen.setdefault(name, urljoin(post_url, href))

    rejected = sum(
        1
        for href in re.findall(r'href="([^"]+)"', response.text)
        if href.lower().endswith(".zip") and not is_safe_filename(href.rsplit("/", 1)[-1])
    )
    if rejected:
        log.debug("%s: skipped %d non-capture archive(s)", post_url, rejected)
    return sorted(seen.items())


def download(session: requests.Session, url: str, dest: Path) -> Path:
    if dest.exists() and dest.stat().st_size > 0:
        log.debug("already downloaded: %s", dest.name)
        return dest

    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_suffix(dest.suffix + ".part")
    with session.get(url, timeout=180, stream=True) as response:
        response.raise_for_status()
        with partial.open("wb") as fh:
            for chunk in response.iter_content(chunk_size=1 << 16):
                fh.write(chunk)
    partial.replace(dest)
    log.info("downloaded %s (%.1f MB)", dest.name, dest.stat().st_size / 1e6)
    return dest


def extract(archive: Path, dest_dir: Path, password: str) -> list[Path]:
    """Extract permitted members, refusing path traversal and anything not a capture or note."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    with pyzipper.AESZipFile(archive) as zf:
        zf.setpassword(password.encode())
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = Path(info.filename).name
            if Path(info.filename).suffix.lower() not in ALLOWED_MEMBER_SUFFIXES:
                log.warning("%s: refusing member %s", archive.name, info.filename)
                continue
            if DENY.search(name):
                log.warning("%s: refusing member %s", archive.name, info.filename)
                continue

            target = dest_dir / name
            if target.exists() and target.stat().st_size == info.file_size:
                written.append(target)
                continue
            with zf.open(info) as src, target.open("wb") as dst:
                while chunk := src.read(1 << 16):
                    dst.write(chunk)
            log.info("extracted %s", target.name)
            written.append(target)

    return written


def fetch_case(case: dict[str, Any]) -> list[Path]:
    """Download and extract every capture for one case. Returns the extracted pcap paths."""
    case_id = case["id"]
    post_url = case["post"]
    password = load_env().get("MTA_ZIP_PASSWORD") or derive_password(post_url)

    session = _session()
    files = scrape_post(session, post_url)
    if not files:
        log.warning("%s: no capture files found at %s", case_id, post_url)
        return []

    raw_dir = DATA_RAW / case_id
    pcap_dir = DATA_PCAP / case_id
    extracted: list[Path] = []

    for name, url in files:
        archive = download(session, url, raw_dir / name)
        try:
            extracted.extend(extract(archive, pcap_dir, password))
        except RuntimeError as exc:
            log.error("%s: cannot open %s (%s) - wrong password?", case_id, name, exc)

    pcaps = [p for p in extracted if p.suffix.lower() in {".pcap", ".pcapng"}]
    log.info("%s: %d capture file(s) ready", case_id, len(pcaps))
    return pcaps


def fetch_all(cases: Iterable[dict[str, Any]]) -> dict[str, list[Path]]:
    return {case["id"]: fetch_case(case) for case in cases}
