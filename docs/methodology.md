# Methodology

How each signal is derived, why it was derived that way, and where it breaks down.

## Source data

Captures come from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net),
which publishes real infection traffic recorded in an instrumented lab. Each post ships the
capture alongside an analyst-written indicator list, and that second file is what makes the
dataset useful beyond demonstration: it is independent ground truth to measure the parsers
against.

Five cases were chosen to cover structurally different behaviour rather than five variations
on one theme. An infostealer that exfiltrates over a bespoke protocol, a RAT that holds a
single socket open, a loader with a large domain footprint, a RAT reached through dynamic DNS,
and a worm that tunnels everything through Tor exercise different parts of the pipeline.

The posts also host live malware binaries. `src/nbm/fetch.py` enforces an allowlist that
accepts only `*.pcap.zip` and `*IOCs*.txt.zip`, a denylist that rejects anything resembling an
executable or email, and applies the same filter again to the members inside each archive.
Nothing downloaded is executed. Archive passwords follow `infected_YYYYMMDD` using the post
date, which the fetcher derives from the post URL.

## Reading the capture

`pcapread.py` makes exactly one pass over each file and produces everything downstream needs,
so a 74 MB capture is never read twice.

**Flow orientation.** A bare SYN identifies the client outright. When the capture begins
mid-connection or the protocol is UDP there is no SYN to rely on, so the lower port number is
assumed to be the server. This is a heuristic and it is wrong for peer-to-peer traffic between
two high ports.

**TCP reassembly.** Payload is written into a per-direction buffer at its sequence offset,
which handles reordering and discards retransmissions naturally. Reassembly is capped at 1 MB
per direction: request and response headers live at the start of a stream, so the cap costs
nothing for protocol analysis while keeping large captures in memory. Each buffer also records
`(offset, timestamp)` marks, which is what allows a parsed HTTP message to be mapped back to
the moment it arrived rather than to the start of the connection.

## DNS

Queries are joined to their responses by `(transaction id, name, type)`. A response without a
matching query is still recorded, because it establishes a name-to-address mapping that lets
later flows be attributed to a domain even when the lookup happened before the capture started.

A suffix list filters operating system and browser background noise so that interesting names
are not buried. That filter has a carve-out: hosts such as `firebasestorage.googleapis.com`
are excluded from it, because staging payloads on a reputable cloud provider is a standard
technique and a naive benign-suffix list hides exactly the traffic worth seeing.

## HTTP

Messages are split by hand rather than with `dpkt.http`, so each one keeps its byte offset and
therefore its timestamp. The parser walks header blocks, resolves body length from
`Content-Length` or `Transfer-Encoding`, and resynchronises past anything that does not look
like a message.

The first bytes of every response body are checked against a table of magic values. A body
beginning `MZ` while the server declares `text/html` is recorded as a content type mismatch,
which is a stronger and far more durable signal than any individual URL.

## TLS

JA3, JA3S, JA4 and JA4S are implemented directly from the ClientHello and ServerHello rather
than taken from a library, so the field handling is visible and testable. GREASE code points
(RFC 8701) are stripped everywhere; their entire purpose is to vary between connections, and
including them would make the fingerprint unstable.

```
JA3  = md5(version,ciphers,extensions,curves,point_formats)          decimal, dash-joined
JA4  = <proto><ver><sni><nciphers><nexts><alpn>
       _<sha256(sorted ciphers)[:12]>
       _<sha256(sorted extensions [+ "_" + sigalgs])[:12]>
JA3S = md5(version,cipher,extensions)
JA4S = <proto><ver><nexts><alpn>_<cipher>_<sha256(extensions in order)[:12]>
```

Two details are easy to get wrong and are covered by the self-test in `tools/validate.py`:
the TLS version in JA4 comes from the highest value in the `supported_versions` extension
rather than the legacy record version, and SNI and ALPN are counted in the JA4 prefix but
deliberately excluded from the extension hash so the fingerprint tracks the client rather than
the destination it happens to be visiting.

**What fingerprints are actually worth.** Across these five cases the JA4
`t12d180700_4b22cbed5bed_2dae41c691ec` appears in the GuLoader, NetSupport and Raspberry Robin
captures. It is not a malware fingerprint; it is the default Windows schannel client, and any
application using the OS TLS stack produces it. Treated as a standalone indicator it would be
useless. Treated as a grouping key, it is valuable: it says these samples all use the system
TLS library rather than a bundled one, and it makes "this fingerprint to this destination" a
usable pivot.

## Beaconing

Three channel shapes are scored, because malware beacons in three different ways:

| Kind | Timed from | Catches |
|---|---|---|
| `connection` | flow start times | a fresh connection per check-in |
| `http` | request timestamps | check-ins multiplexed over one keep-alive connection |
| `keepalive` | client-to-server data packets in one socket | a RAT holding a session open |

The third matters more than it might appear. Both the Remcos and the NetSupport samples in
this dataset open a single connection and hold it for the length of the capture. Measured by
connection count they show no cadence whatsoever; measured by packet rhythm inside the socket,
Remcos checks in every 30.5 seconds with 0.4% jitter and NetSupport every 60.1 seconds with
0.1%.

**Debouncing.** Events within one second are collapsed into a single check-in. Browsers and
malware alike open several parallel sockets per contact, and without this the interval series
is dominated by near-zero deltas.

**Why median absolute deviation.** Jitter is `MAD / median`, not the standard deviation. MAD
is resistant to outliers, so a single long pause (a retry after a failed connection, the
analyst stepping away) does not hide an otherwise metronomic pattern the way a variance-based
measure would.

**Score.** `55% regularity + 30% repetition + 15% payload uniformity`, each normalised to
0-1. Regularity dominates because it is the defining property of a beacon. Repetition guards
against calling three coincidentally-spaced connections a pattern. Payload uniformity
separates scripted check-ins from human-driven traffic of varying size.

**Cadence class.** Score alone is misleading, so every candidate is also classified by its
interval. Tor padding on tcp/9001 in the Raspberry Robin capture is more regular (1.1 second
median, 4.4% jitter, score 88.1) than any genuine C2 in the dataset, and would otherwise
outrank the 30-second Remcos heartbeat. Sub-10-second cadences are almost always transport
keepalive or padding; 10 to 300 seconds is where commodity C2 lives.

## Known limitations

**Benign software beacons too.** The Latrodectus capture produces a score of 76.0 for
`client.wns.windows.com` at a 245-second interval with 0.0% jitter. That is the Windows Push
Notification Service behaving exactly as designed. It is a true detection of periodicity and a
false positive for malice, and it is the clearest argument in this dataset that beacon scoring
must be baselined per environment rather than alerted on directly.

**Encrypted payloads are inferred, not observed.** When delivery happens over TLS the pipeline
cannot see the file. It infers payload retrieval from transfer volume on a first-contact
non-benign host, which is weaker than the magic-byte check available in cleartext, and will
misfire on any large legitimate download to an unrecognised domain.

**Phase labels are heuristics.** Initial access, delivery, check-in and exfiltration are
inferred from ordering, direction and volume. They are a reading of the traffic, not ground
truth, and a capture that begins after the intrusion started will have its earliest events
mislabelled.

**Single-capture view.** Every conclusion is drawn from one recording of one infection on one
host. Cadence measured over 26 minutes may not hold over days, and infrastructure seen here
has almost certainly rotated since.

**Chunked encoding is not decoded.** Chunked response bodies are consumed to the end of the
stream rather than de-chunked, so `resp_body_len` overstates the true body size for those
responses. Magic-byte sniffing still works, because the first chunk header is short and the
body follows immediately.

## Validation

`python tools/validate.py` runs four independent checks:

1. **TLS fingerprint self-test** - a synthetic ClientHello with GREASE in the cipher list, the
   extension list and the supported groups, asserting that GREASE is stripped and that JA3 and
   JA4 are assembled from the correct fields.
2. **Suricata syntax** - all generated rules re-parsed with `idstools`.
3. **Sigma validation** - all generated rules re-parsed and checked with `pysigma`.
4. **Indicator recall** - what the parsers recovered against the published IOC list.

Recall against the published lists is not expected to reach 100%, and the gap is informative
rather than a defect. In the Latrodectus case the published list includes
`firebasestorage.googleapis.com` under the heading "2 EXAMPLES OF FIREBASE URLS", describing a
delivery step that precedes the capture, and annotates `kurvabbr.pw` and `barsen.monster` with
"domain no longer resolves to an IP address". Neither could appear in the traffic. The
NetSupport list similarly includes `infosec.exchange` and `threatfox.abuse.ch`, which are
reference links in the write-up rather than indicators. Every address that could be observed,
was: address recall is 100% in two of the three cases that publish one, and 8 of 10 in the
third.
