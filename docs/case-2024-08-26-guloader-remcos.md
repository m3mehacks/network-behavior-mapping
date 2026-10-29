# 2024-08-26-guloader-remcos

**Family:** GuLoader / Remcos RAT  
**Source:** https://www.malware-traffic-analysis.net/2024/08/26/index.html  
**Capture:** 2024-08-26-GuLoader-for-Remcos-RAT.pcap  
**Window:** 2024-08-26T20:38:54.354Z to 2024-08-26T21:31:49.350Z (53 minutes)

GuLoader delivering Remcos RAT, TLS C2 over non-standard ports.

Parsed 1,620 packets into 8 flows, yielding 4 DNS events, 1 HTTP transactions, 2 TLS handshakes and 1 beacon candidates.

## Beaconing cadence

| Score | Destination | Port | Kind | Check-ins | Interval | Jitter | Cadence |
|---|---|---|---|---|---|---|---|
| 86.8 (strong) | janbours92harbu03[.]duckdns[.]org | 3980 | keepalive | 105 | 30s | 0.4% | 10-300s |


The most regular channel is janbours92harbu03[.]duckdns[.]org on port 3980: 105 events at a median of 30 seconds with 0.4% jitter, sustained over 52m21s.

## DNS and C2 domains

| Domain | Lookups | First seen | Resolved to | Response |
|---|---|---|---|---|
| softiq[.]ro | 2 | 20:38:54 | 194[.]36[.]140[.]235 | NOERROR |
| janbours92harbu03[.]duckdns[.]org | 1 | 20:39:26 | 206[.]123[.]148[.]197 | NOERROR |
| geoplugin[.]net | 1 | 20:39:30 | 178[.]237[.]33[.]50 | NOERROR |


## HTTP endpoints

| Time | Method | Endpoint | Status | Response | Body |
|---|---|---|---|---|---|
| 20:39:31 | GET | geoplugin[.]net/json[.]gp | 200 | 952 B | json-or-text |


## TLS fingerprints

| Destination | Port | Version | JA4 | JA4S | JA3 |
|---|---|---|---|---|---|
| softiq[.]ro | 443 | TLS 1.2 | t12d180700_4b22cbed5bed_2dae41c691ec | t120400_c02f_4993ccf7354b | 6a5d235ee78c6aed... |
| softiq[.]ro | 443 | TLS 1.3 | t13d201100_2b729b4bf6f3_9e7b989ebec8 | t130200_1302_234ea6891581 | 3c293bdf2a25c075... |


## Timeline of observed activity

| Time | Phase | Source | Destination | Observation |
|---|---|---|---|---|
| 20:38:54 | dns-resolution | 10.8.26.101 | softiq[.]ro | A query -> NOERROR [194.36.140.235] |
| 20:38:55 | payload-delivery | 10.8.26.101 | softiq[.]ro:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 484874 bytes |
| 20:39:22 | dns-resolution | 10.8.26.101 | softiq[.]ro | A query -> NOERROR [194.36.140.235] |
| 20:39:23 | payload-delivery | 10.8.26.101 | softiq[.]ro:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 499859 bytes |
| 20:39:26 | dns-resolution | 10.8.26.101 | janbours92harbu03[.]duckdns[.]org | A query -> NOERROR [206.123.148.197] |
| 20:39:27 | c2-check-in | 10.8.26.101 | janbours92harbu03[.]duckdns[.]org:3980 | undecoded TCP session, non-standard port, held open 3141s, 13043 bytes out / 2119 bytes in |
| 20:39:28 | c2-check-in | 10.8.26.101 | janbours92harbu03[.]duckdns[.]org:3980 | 105 keepalive check-ins every ~30s (jitter 0%, score 86.8) |
| 20:39:28 | c2-check-in | 10.8.26.101 | janbours92harbu03[.]duckdns[.]org:3980 | undecoded TCP session, non-standard port, 59352 bytes out / 495663 bytes in |
| 20:39:30 | dns-resolution | 10.8.26.101 | geoplugin[.]net | A query -> NOERROR [178.237.33.50] |


## Indicators

Defanged. Machine-readable copies are in `output/2024-08-26-guloader-remcos/iocs.json`.

**Domains**

- `softiq[.]ro` -> 194[.]36[.]140[.]235
- `janbours92harbu03[.]duckdns[.]org` -> 206[.]123[.]148[.]197
- `geoplugin[.]net` -> 178[.]237[.]33[.]50

**Addresses**

- `194[.]36[.]140[.]235` ports 443 (tls)
- `206[.]123[.]148[.]197` ports 3980 (beacon)
- `178[.]237[.]33[.]50` ports 80 (http)

## Detection opportunities

Rules generated from this case are in [../detections/](../detections/); the rationale for each is in [detection-opportunities.md](detection-opportunities.md).
