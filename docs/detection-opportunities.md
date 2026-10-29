# Detection opportunities

What these five captures actually give a defender, ordered by how long each detection stays
useful. Rules live in [../detections/](../detections/), split into an `observed` tier
generated from the indicators in these captures and a `behavioral` tier written from the
patterns they demonstrate.

The split matters. Everything in the observed tier is precise, cheap to run and will be dead
within weeks, because the domains and addresses rotate. Everything in the behavioral tier
survives that rotation but needs a baseline before it can be trusted.

## What was observed

| Case | Family | Delivery | C2 channel | Cadence |
|---|---|---|---|---|
| 2024-10-23 | Redline Stealer | - | SOAP over HTTP to a bare IP, tcp/55123 | none; single 1 MB burst |
| 2024-12-17 | NetSupport RAT | 4.6 MB and 17 MB over TLS from `depostsolo[.]biz` | raw TCP on tcp/443, no TLS | 60.1s, 0.1% jitter |
| 2024-06-25 | Latrodectus | HTTP and TLS, 413 flows | TLS to `garunt[.]biz` and 64.7.198.158 | 60.9s and 113s |
| 2024-08-26 | GuLoader / Remcos | 485 KB over TLS from `softiq[.]ro` | dynamic DNS, tcp/3980 | 30.5s, 0.4% jitter |
| 2024-11-14 | Raspberry Robin | - | Tor, tcp/9001, 110, 444, 28003 | 1.1s (transport padding) |

## Tier 1: behavioural detections

These describe how the malware had to behave, not what it happened to connect to.

### Periodic check-ins

Four of the five cases beacon. Two of them do it inside a single long-lived socket, which is
the detail most beacon detections miss: measured by connection count, Remcos and NetSupport
show no cadence at all.

- Zeek: `NBM::Periodic_Beacon` in
  [nbm-behavioral.zeek](../detections/zeek/nbm-behavioral.zeek), scoring connection start
  times per destination with median absolute deviation as the jitter measure.
- KQL: [nbm-behavioral-beaconing.kql](../detections/kql/nbm-behavioral-beaconing.kql). KQL has
  no median-of-deviations, so it uses standard deviation with a looser 25% threshold; one long
  gap inflates the spread, which is the cost of that substitution.

ATT&CK: T1071 Application Layer Protocol, T1573 Encrypted Channel.

**Tuning.** `client.wns.windows.com` in the Latrodectus capture scores 76.0 at a 245-second
interval with 0.0% jitter. That is the Windows Push Notification Service working correctly.
Beacon scoring finds periodicity, not malice, and must be baselined against your own
environment before it drives an alert. Read the cadence class alongside the score: sub-10
second intervals are transport keepalive, and 10 to 300 seconds is where commodity C2 lives.

### Protocol masquerade on tcp/443

The NetSupport RAT sends 7,297 bytes to 194.180.191.64 on port 443 and never presents a TLS
ClientHello. The port was chosen to pass egress filtering, not because TLS is in use. This is
cheap to detect and very hard for an operator to avoid without implementing real TLS.

- Suricata: SID 9005000, matching an established session to port 443 whose first client bytes
  are not a `16 03` TLS record header.
- Zeek: `NBM::TLS_Port_Without_TLS`, which reports at connection teardown if no
  `ssl_client_hello` fired.

ATT&CK: T1571 Non-Standard Port, T1095 Non-Application Layer Protocol.

### TLS on ports that are not TLS ports

The inverse, and Raspberry Robin does it comprehensively: genuine TLS handshakes on tcp/80,
110, 444, 9001 and 28003. Tor deliberately chooses ports that firewalls leave open.

- Suricata: SID 9005001. Zeek: `NBM::TLS_On_Unexpected_Port`.

ATT&CK: T1571 Non-Standard Port.

### Long-lived sessions to uncommon ports

Remcos held tcp/3980 open for 52 minutes. Raspberry Robin used tcp/9001, 110 and 28003. A
persistent RAT socket has a distinctive shape: low volume, long duration, unusual port.

- Sigma:
  [nbm-behavioral-c2-nonstandard-port.yml](../detections/sigma/nbm-behavioral-c2-nonstandard-port.yml)
- KQL:
  [nbm-behavioral-nonstandard-port-c2.kql](../detections/kql/nbm-behavioral-nonstandard-port-c2.kql)

The port list is exclusive rather than inclusive, so this needs an environment baseline. Line
of business applications, VPNs and game clients all live on odd ports.

ATT&CK: T1571 Non-Standard Port.

### Executable served under a non-executable content type

A response body starting `MZ` while the server declares `text/` or `image/`. Legitimate
software distribution has no reason to disguise what it is serving. This fires at the delivery
step, which is earlier in the intrusion than any C2 detection and therefore worth more.

- Suricata: SID 9005002. Sigma:
  [nbm-behavioral-executable-content-type-mismatch.yml](../detections/sigma/nbm-behavioral-executable-content-type-mismatch.yml)

ATT&CK: T1105 Ingress Tool Transfer.

### HTTP POST to a bare IP with no User-Agent

Redline posted roughly 1 MB of stolen data as SOAP XML to `188.190.10.10:55123`, with no
User-Agent header and no preceding DNS lookup. Each property is individually weak; together
they are close to diagnostic, because browsers send a User-Agent and normal applications
resolve a name first.

- Suricata: SID 9005003. Sigma:
  [nbm-behavioral-http-bare-ip-no-useragent.yml](../detections/sigma/nbm-behavioral-http-bare-ip-no-useragent.yml)

ATT&CK: T1041 Exfiltration Over C2 Channel, T1071.001 Web Protocols.

### Dynamic DNS resolution

GuLoader's Remcos payload resolved `janbours92harbu03.duckdns.org` immediately before opening
the tcp/3980 session. Commodity RATs favour free dynamic DNS because the operator can repoint
the name without rebuilding the implant.

- Suricata: SID 9005004. Sigma:
  [nbm-behavioral-dynamic-dns-c2.yml](../detections/sigma/nbm-behavioral-dynamic-dns-c2.yml)
- KQL: [nbm-behavioral-dynamic-dns.kql](../detections/kql/nbm-behavioral-dynamic-dns.kql),
  which correlates the lookup with what the resolving process connected to next. The
  correlation is what makes it usable; the lookup alone is noisy.

ATT&CK: T1568 Dynamic Resolution, T1071.004 DNS.

## Tier 2: observed indicators

Generated automatically from the captures: 218 Suricata rules covering DNS queries, TLS SNI,
HTTP endpoints, JA3 hashes and destination addresses, plus equivalent Zeek sets and Sigma and
KQL lists.

These are worth deploying and worth expiring. Treat them as a tripwire for this specific
campaign infrastructure, not as coverage.

- Suricata: [nbm-observed.rules](../detections/suricata/nbm-observed.rules)
- Zeek: [nbm-observed.zeek](../detections/zeek/nbm-observed.zeek), which uses only base Zeek
  and matches on DNS queries, TLS SNI and destination addresses
- Zeek: [nbm-observed-ja3.zeek](../detections/zeek/nbm-observed-ja3.zeek), kept separate
  because it requires the JA3 package (`zkg install zeek/salesforce/ja3`)
- Sigma: `nbm-observed-*.yml`
- KQL: [nbm-observed-c2-indicators.kql](../detections/kql/nbm-observed-c2-indicators.kql)

## A note on JA3 and JA4 as indicators

The JA4 `t12d180700_4b22cbed5bed_2dae41c691ec` appears in three of the five captures, spanning
GuLoader, NetSupport and Raspberry Robin. It is not a malware signature. It is the default
Windows schannel client, produced by anything using the operating system's TLS stack.

Alerting on it alone would be a mistake. It is still useful in two ways: as a grouping key
when hunting, and as a contradiction detector, because a fingerprint that claims to be one
thing while the User-Agent claims another is itself a finding. The generated JA3 rules are in
the observed tier for that reason, and should be scoped to a destination before deployment.

Note also that neither Suricata nor base Zeek computes JA4 today. The pipeline records it in
`output/<case>/tls.csv` and carries it in Suricata rule metadata so the value is available for
hunting and for platforms that do support it, but the deployable TLS fingerprint rules match
on JA3.

## What these captures do not cover

Worth stating plainly, because a detection set is judged as much by its gaps.

- **No DNS tunnelling and no DNS-over-HTTPS.** Both would defeat the DNS-based detections here.
- **No domain generation algorithm.** `www.sdeq3iozavf.com` in the Raspberry Robin capture
  looks algorithmic but is Tor's fabricated SNI, not a resolvable DGA domain.
- **No cloud-service C2.** No case here uses Slack, Telegram or Google Drive as a channel,
  where destination-based detection collapses entirely.
- **No lateral movement or internal traffic.** Every capture is a single host talking outbound.
- **Short observation windows.** The longest capture is 2 hours 46 minutes. A beacon with a
  daily cadence would be invisible.

## Deployment order

If only some of this can be adopted, this is the order that returns the most:

1. Executable under a mismatched content type. High precision, fires at delivery.
2. tcp/443 without a TLS ClientHello. High precision, near-zero legitimate traffic.
3. TLS on an unexpected port. Needs light tuning.
4. Beacon scoring. Highest value, but requires a baseline before it is trustworthy.
5. Observed indicators. Deploy, then expire on a schedule.
