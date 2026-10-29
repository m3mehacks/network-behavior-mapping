#!/usr/bin/env python3
"""Validate the pipeline's output and the detection content it generates.

Four checks, each independent of the code that produced the thing being checked:

  1. TLS fingerprint self-test - a synthetic ClientHello with known contents, verifying that
     GREASE is stripped and that JA3 and JA4 are assembled from the right fields.
  2. Suricata syntax        - every generated rule is re-parsed with idstools.
  3. Sigma validation       - every generated rule is re-parsed and checked with pysigma.
  4. Indicator recall       - what the parsers recovered versus the analyst-written IOC list
                              shipped with each capture.

Run: python tools/validate.py
"""

from __future__ import annotations

import glob
import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nbm.tls import is_grease, ja3, ja4, parse_client_hello  # noqa: E402

PASS = "PASS"
FAIL = "FAIL"
failures = 0


def report(name: str, ok: bool, detail: str = "") -> None:
    global failures
    if not ok:
        failures += 1
    print(f"[{PASS if ok else FAIL}] {name}" + (f" - {detail}" if detail else ""))


# ---------------------------------------------------------------------------------------
# 1. TLS fingerprint self-test
# ---------------------------------------------------------------------------------------


def _ext(ext_type: int, body: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(body)) + body


def _build_client_hello() -> tuple[bytes, dict]:
    """A ClientHello with deliberately awkward contents: GREASE in the cipher list, the
    extension list and the supported groups, plus SNI, ALPN and supported_versions."""
    greased_ciphers = [0x0A0A, 0x1301, 0x1302, 0xC02F, 0xC030]
    real_ciphers = [0x1301, 0x1302, 0xC02F, 0xC030]

    sni_host = b"example-c2.test"
    sni_body = struct.pack("!HBH", len(sni_host) + 3, 0, len(sni_host)) + sni_host

    alpn_protos = [b"h2", b"http/1.1"]
    alpn_inner = b"".join(bytes([len(p)]) + p for p in alpn_protos)
    alpn_body = struct.pack("!H", len(alpn_inner)) + alpn_inner

    groups = [0x1A1A, 0x001D, 0x0017]  # first is GREASE
    groups_body = struct.pack("!H", len(groups) * 2) + b"".join(
        struct.pack("!H", g) for g in groups
    )

    point_formats_body = bytes([1, 0])

    sig_algs = [0x0403, 0x0804, 0x0401]
    sig_body = struct.pack("!H", len(sig_algs) * 2) + b"".join(
        struct.pack("!H", s) for s in sig_algs
    )

    versions = [0x2A2A, 0x0304, 0x0303]  # first is GREASE
    versions_body = bytes([len(versions) * 2]) + b"".join(
        struct.pack("!H", v) for v in versions
    )

    extensions = (
        _ext(0x3A3A, b"")  # GREASE extension, must be dropped entirely
        + _ext(0x0000, sni_body)
        + _ext(0x000A, groups_body)
        + _ext(0x000B, point_formats_body)
        + _ext(0x000D, sig_body)
        + _ext(0x0010, alpn_body)
        + _ext(0x002B, versions_body)
    )

    body = (
        struct.pack("!H", 0x0303)
        + b"\x00" * 32
        + bytes([0])
        + struct.pack("!H", len(greased_ciphers) * 2)
        + b"".join(struct.pack("!H", c) for c in greased_ciphers)
        + bytes([1, 0])
        + struct.pack("!H", len(extensions))
        + extensions
    )

    handshake = bytes([0x01]) + len(body).to_bytes(3, "big") + body
    record = bytes([0x16]) + struct.pack("!HH", 0x0301, len(handshake)) + handshake

    expected = {
        "ciphers": real_ciphers,
        "extensions": [0x0000, 0x000A, 0x000B, 0x000D, 0x0010, 0x002B],
        "curves": [0x001D, 0x0017],
        "point_formats": [0],
        "sig_algs": sig_algs,
        "sni": "example-c2.test",
        "alpn": ["h2", "http/1.1"],
        "supported_versions": [0x0304, 0x0303],
    }
    return record, expected


def check_tls_fingerprints() -> None:
    print("\n--- TLS fingerprinting self-test ---")

    report(
        "GREASE code points recognised",
        all(is_grease(v) for v in (0x0A0A, 0x1A1A, 0x3A3A, 0xFAFA))
        and not any(is_grease(v) for v in (0x1301, 0xC02F, 0x0000, 0x002B)),
    )

    record, expected = _build_client_hello()
    hello = parse_client_hello(record)
    if hello is None:
        report("ClientHello parses", False, "parser returned None")
        return
    report("ClientHello parses", True)

    for field, want in expected.items():
        got = getattr(hello, field)
        report(f"  {field} == {want}", got == want, f"got {got}")

    # JA3 must be the MD5 of the decimal, dash-joined field string with GREASE removed.
    want_ja3_string = (
        "771,"
        + "-".join(str(c) for c in expected["ciphers"])
        + ","
        + "-".join(str(e) for e in expected["extensions"])
        + ","
        + "-".join(str(c) for c in expected["curves"])
        + ","
        + "-".join(str(p) for p in expected["point_formats"])
    )
    got_ja3, got_ja3_string = ja3(hello)
    report("JA3 string built from the right fields", got_ja3_string == want_ja3_string,
           f"got {got_ja3_string}")
    report("JA3 hash is MD5 of that string",
           got_ja3 == hashlib.md5(want_ja3_string.encode()).hexdigest())

    # JA4_a: t (TCP) + 13 (highest supported_version) + d (SNI present) + 04 ciphers
    # + 06 extensions + h2 (first and last char of the first ALPN entry).
    got_ja4 = ja4(hello)
    ja4_a, ja4_b, ja4_c = got_ja4.split("_")
    report("JA4_a == t13d0406h2", ja4_a == "t13d0406h2", f"got {ja4_a}")

    want_b = hashlib.sha256(
        ",".join(sorted(f"{c:04x}" for c in expected["ciphers"])).encode()
    ).hexdigest()[:12]
    report("JA4_b is truncated SHA256 of the sorted cipher list", ja4_b == want_b,
           f"got {ja4_b}, want {want_b}")

    # SNI (0x0000) and ALPN (0x0010) are counted in JA4_a but excluded from the JA4_c hash.
    exts_for_hash = sorted(
        f"{e:04x}" for e in expected["extensions"] if e not in (0x0000, 0x0010)
    )
    want_c = hashlib.sha256(
        (
            ",".join(exts_for_hash)
            + "_"
            + ",".join(f"{s:04x}" for s in expected["sig_algs"])
        ).encode()
    ).hexdigest()[:12]
    report("JA4_c excludes SNI and ALPN and appends signature algorithms", ja4_c == want_c,
           f"got {ja4_c}, want {want_c}")


# ---------------------------------------------------------------------------------------
# 2 & 3. Generated rule syntax
# ---------------------------------------------------------------------------------------


def check_suricata() -> None:
    print("\n--- Suricata rule syntax (idstools) ---")
    try:
        from idstools import rule as idsrule
    except ImportError:
        report("idstools available", False, "pip install idstools")
        return

    total = bad = 0
    for path in sorted(glob.glob(str(ROOT / "detections" / "suricata" / "*.rules"))):
        for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            total += 1
            try:
                if idsrule.parse(line) is None:
                    raise ValueError("parser returned None")
            except Exception as exc:  # noqa: BLE001
                bad += 1
                print(f"       {Path(path).name}:{lineno}: {exc}")
    report(f"{total - bad}/{total} rules parse", bad == 0)


def check_sigma() -> None:
    print("\n--- Sigma rule validation (pysigma) ---")
    try:
        result = subprocess.run(
            [sys.executable, "-c", "from sigma.cli.main import main; main()",
             "check", str(ROOT / "detections" / "sigma")],
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        report("sigma-cli available", False, str(exc))
        return

    output = result.stdout + result.stderr
    ok = "Found 0 errors, 0 condition errors and 0 issues." in output
    count = len(list((ROOT / "detections" / "sigma").glob("*.yml")))
    report(f"{count} rules validate", ok, "" if ok else output.strip()[-400:])


# ---------------------------------------------------------------------------------------
# 4. Indicator recall
# ---------------------------------------------------------------------------------------


def check_recall() -> None:
    print("\n--- Indicator recall against published IOC lists ---")
    rows = []
    for path in sorted(glob.glob(str(ROOT / "output" / "*" / "iocs.json"))):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        xref = data["cross_reference"]
        if not (xref["published_domains"] or xref["published_ips"]):
            continue
        rows.append(
            (
                data["case"],
                f"{len(xref['matched_domains'])}/{xref['published_domains']}",
                f"{len(xref['matched_ips'])}/{xref['published_ips']}",
                xref["published_only_domains"][:4],
            )
        )

    if not rows:
        report("cases with a published IOC list", False, "none found; run 'cli.py analyze'")
        return

    print(f"    {'case':<32}{'domains':<10}{'addresses':<12}")
    for case, dom, ip, missed in rows:
        print(f"    {case:<32}{dom:<10}{ip:<12}")
        if missed:
            print(f"        not recovered: {', '.join(missed)}")
    report(f"{len(rows)} case(s) cross-checked", True)


def main() -> int:
    check_tls_fingerprints()
    check_suricata()
    check_sigma()
    check_recall()
    print(f"\n{'All checks passed.' if not failures else f'{failures} check(s) failed.'}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
