# 2024-10-23-redline-stealer

**Family:** Redline Stealer  
**Source:** https://www.malware-traffic-analysis.net/2024/10/23/index.html  
**Capture:** 2024-10-23-Redline-Stealer-infection-traffic.pcap  
**Window:** 2024-10-23T19:15:32.142Z to 2024-10-23T19:15:57.818Z (0 minutes)

Infostealer infection with HTTP-based exfiltration.

Parsed 8,807 packets into 3 flows, yielding 1 DNS events, 3 HTTP transactions, 1 TLS handshakes and 0 beacon candidates.

## Beaconing cadence

_No channel met the scoring threshold. Either the capture is too short for a cadence to emerge, or the malware communicates only on demand._

## DNS and C2 domains

| Domain | Lookups | First seen | Resolved to | Response |
|---|---|---|---|---|
| api[.]ip[.]sb | 1 | 19:15:38 | 104[.]26[.]13[.]31, 172[.]67[.]75[.]172, 104[.]26[.]12[.]31 | NOERROR |


## HTTP endpoints

| Time | Method | Endpoint | Status | Response | Body |
|---|---|---|---|---|---|
| 19:15:32 | POST | 188[.]190[.]10[.]10:55123/ | 100 | 6028 B | - |
| 19:15:37 | POST | 188[.]190[.]10[.]10:55123/ | - | 0 B | - |
| 19:15:42 | POST | 188[.]190[.]10[.]10:55123/ | - | 0 B | - |


## TLS fingerprints

| Destination | Port | Version | JA4 | JA4S | JA3 |
|---|---|---|---|---|---|
| api[.]ip[.]sb | 443 | TLS 1.0 | t10d060600_4dc025c38c38_950472255fe9 | t100500_c013_b508675693ed | 8fffe46776bf62f4... |


## Timeline of observed activity

| Time | Phase | Source | Destination | Observation |
|---|---|---|---|---|
| 19:15:38 | dns-resolution | 10.10.23.101 | api[.]ip[.]sb | A query -> NOERROR [104.26.13.31, 172.67.75.172, 104.26.12.31] |
| 19:15:42 | exfiltration | 10.10.23.101 | 188[.]190[.]10[.]10:55123 | POST /, sent 1046820 bytes |


## Indicators

Defanged. Machine-readable copies are in `output/2024-10-23-redline-stealer/iocs.json`.

**Domains**

- `188[.]190[.]10[.]10` -> 188[.]190[.]10[.]10
- `api[.]ip[.]sb` -> 104[.]26[.]13[.]31, 172[.]67[.]75[.]172, 104[.]26[.]12[.]31

**Addresses**

- `188[.]190[.]10[.]10` ports 55123 (http)
- `104[.]26[.]13[.]31` ports 443 (tls)

## Cross-check against the published IOC list

The capture ships with an analyst-written indicator list. Comparing it with what the parsers recovered independently is this project's accuracy control.

| Indicator type | Published | Recovered | Recall |
|---|---|---|---|
| domains | 3 | 1 | 33% |
| ips | 2 | 2 | 100% |


Present in the published list but not recovered from the capture (these are typically file hashes, sandbox-only artifacts, or names listed as context rather than contacted):

`188-190-10-10[.]clevhosting[.]com`, `ad-hardware[.]com`

## Detection opportunities

Rules generated from this case are in [../detections/](../detections/); the rationale for each is in [detection-opportunities.md](detection-opportunities.md).
