# Network Behavior Mapping from Malware PCAPs

Turns real malware infection packet captures into a structured behavioural map and a set of
detection opportunities. For each case the pipeline extracts:

- **DNS** resolutions and the C2 domains behind them
- **HTTP** endpoints, methods, user agents and response types
- **TLS** metadata including SNI and JA3 / JA4 / JA3S / JA4S fingerprints
- **Beaconing cadence** scored on interval regularity, jitter and payload uniformity

and produces a phase-labelled activity timeline plus Suricata, Zeek, Sigma and KQL rules.

Captures come from [malware-traffic-analysis.net](https://www.malware-traffic-analysis.net),
Brad Duncan's public collection of real infection traffic.

## Safety

The blog posts that host these captures also host **live malware binaries**. This project never
downloads them. `src/nbm/fetch.py` enforces an allowlist that accepts only `*.pcap.zip` and
`*IOCs*.txt.zip`, backed by a denylist that rejects anything resembling an executable, archive of
samples or email file. Nothing downloaded is ever executed, and everything lands in gitignored
`data/`.

Analysis is entirely passive parsing of capture files. You do not need to detonate anything.

## Setup

```bash
pip install -r requirements.txt
```

The archives are password protected, using the scheme `infected_YYYYMMDD` where the date is the
blog post date. The pipeline derives this from each case's post URL, so there is no secret to
configure. The site notes that individual posts may deviate from the scheme; if one does, copy
`.env.example` to `.env` and set `MTA_ZIP_PASSWORD` to override.

## Usage

```bash
python cli.py fetch              # download and extract captures for every case
python cli.py analyze            # parse captures into output/<case>/*.csv|json
python cli.py report             # write docs/case-<id>.md
python cli.py rules              # emit detections/{suricata,zeek,sigma,kql}
python cli.py all                # everything, in order

python cli.py all --case 2024-10-23-redline-stealer   # limit to one case
python cli.py analyze -v                              # debug logging
```

Cases are declared in [config/cases.yaml](config/cases.yaml); adding one is a four-line entry
pointing at a post URL.

## Validation

```bash
pip install sigma-cli idstools     # optional, for the rule syntax checks
python tools/validate.py
```

Four independent checks: a TLS fingerprint self-test against a synthetic ClientHello carrying
GREASE, Suricata rule syntax via `idstools`, Sigma validation via `pysigma`, and indicator
recall against the analyst-written IOC list shipped with each capture.

## Layout

```
config/cases.yaml       case definitions
src/nbm/fetch.py        post scraping, allowlist enforcement, AES extraction
src/nbm/pcapread.py     dpkt packet loop, flow table, TCP payload reassembly
src/nbm/dnsx.py         DNS queries, answers, domain-to-IP mapping
src/nbm/httpx.py        HTTP requests and responses
src/nbm/tls.py          ClientHello/ServerHello parsing, JA3/JA4/JA3S/JA4S
src/nbm/beacon.py       interval statistics and beacon scoring
src/nbm/timeline.py     merged, phase-labelled event stream
src/nbm/iocs.py         deduplicated indicator export
src/nbm/report.py       per-case markdown reports
src/nbm/rules.py        Suricata / Zeek / Sigma / KQL emitters
tools/validate.py       self-tests and rule linting
output/<case>/          generated CSV and JSON
docs/                   methodology, per-case reports, detection opportunities
```

## Selected findings

- **Remcos** held a single socket open on tcp/3980 for 52 minutes, checking in every 30.5
  seconds with 0.4% jitter. Measured by connection count it shows no cadence at all, which is
  why the pipeline scores packet rhythm inside long-lived sockets as well as connection starts.
- **NetSupport RAT** sent 7,297 bytes to tcp/443 without ever presenting a TLS ClientHello.
  The port was chosen to pass egress filtering, not because TLS was in use.
- **Redline Stealer** posted roughly 1 MB of stolen data as SOAP XML to a bare IP on tcp/55123
  with no User-Agent and no preceding DNS lookup.
- **Raspberry Robin** ran genuine TLS on tcp/80, 110, 444, 9001 and 28003 - Tor choosing ports
  that firewalls leave open.
- The JA4 `t12d180700_4b22cbed5bed_2dae41c691ec` appears in three unrelated families. It is
  the default Windows schannel client, not a malware signature - a useful reminder that a TLS
  fingerprint is a grouping key rather than an indicator.

## Documentation

- [docs/methodology.md](docs/methodology.md) - how each signal is derived and what its limits are
- [docs/detection-opportunities.md](docs/detection-opportunities.md) - the detection rationale
  across all cases, mapped to ATT&CK
- `docs/case-<id>.md` - per-case findings and timeline
