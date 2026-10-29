# 2024-12-17-netsupport-rat

**Family:** NetSupport RAT  
**Source:** https://www.malware-traffic-analysis.net/2024/12/17/index.html  
**Capture:** 2024-12-17-SmartApeSG-to-NetSupport-RAT.pcap  
**Window:** 2024-12-17T02:31:21.760Z to 2024-12-17T02:58:04.855Z (27 minutes)

SmartApeSG injected script leading to NetSupport RAT check-ins.

Parsed 16,931 packets into 16 flows, yielding 4 DNS events, 2 HTTP transactions, 9 TLS handshakes and 1 beacon candidates.

## Beaconing cadence

| Score | Destination | Port | Kind | Check-ins | Interval | Jitter | Cadence |
|---|---|---|---|---|---|---|---|
| 89.7 (strong) | 194[.]180[.]191[.]64 | 443 | keepalive | 27 | 60s | 0.1% | 10-300s |


The most regular channel is 194[.]180[.]191[.]64 on port 443: 27 events at a median of 60 seconds with 0.1% jitter, sustained over 26m04s.

## DNS and C2 domains

| Domain | Lookups | First seen | Resolved to | Response |
|---|---|---|---|---|
| banks-canada[.]com | 1 | 02:31:21 | 34[.]42[.]173[.]126 | NOERROR |
| depostsolo[.]biz | 1 | 02:31:22 | 185[.]33[.]84[.]25 | NOERROR |
| taktlat[.]xyz | 1 | 02:31:22 | 185[.]33[.]84[.]25 | NOERROR |
| geo[.]netsupportsoftware[.]com | 1 | 02:32:00 | 104[.]26[.]0[.]231, 104[.]26[.]1[.]231, 172[.]67[.]68[.]212 | NOERROR |


## HTTP endpoints

| Time | Method | Endpoint | Status | Response | Body |
|---|---|---|---|---|---|
| 02:32:00 | GET | geo[.]netsupportsoftware[.]com/location/loca[.]asp | 404 | 327 B | - |
| 02:32:01 | GET | geo[.]netsupportsoftware[.]com/location/loca[.]asp | 200 | 27 B | - |


## TLS fingerprints

| Destination | Port | Version | JA4 | JA4S | JA3 |
|---|---|---|---|---|---|
| banks-canada[.]com | 443 | TLS 1.2 | t12d180700_4b22cbed5bed_2dae41c691ec | t120400_c030_eaf502adc2b6 | 6a5d235ee78c6aed... |
| taktlat[.]xyz | 443 | TLS 1.2 | t12d180700_4b22cbed5bed_2dae41c691ec | t120400_c030_eaf502adc2b6 | 6a5d235ee78c6aed... |
| depostsolo[.]biz | 443 | TLS 1.2 | t12d180700_4b22cbed5bed_2dae41c691ec | t120400_c030_eaf502adc2b6 | 6a5d235ee78c6aed... |


## Timeline of observed activity

| Time | Phase | Source | Destination | Observation |
|---|---|---|---|---|
| 02:31:21 | dns-resolution | 10.12.17.101 | banks-canada[.]com | A query -> NOERROR [34.42.173.126] |
| 02:31:22 | initial-access | 10.12.17.101 | banks-canada[.]com:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 57666 bytes |
| 02:31:22 | dns-resolution | 10.12.17.101 | depostsolo[.]biz | A query -> NOERROR [185.33.84.25] |
| 02:31:22 | dns-resolution | 10.12.17.101 | taktlat[.]xyz | A query -> NOERROR [185.33.84.25] |
| 02:31:23 | initial-access | 10.12.17.101 | taktlat[.]xyz:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 4916 bytes |
| 02:31:23 | initial-access | 10.12.17.101 | depostsolo[.]biz:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 4925 bytes |
| 02:31:24 | payload-delivery | 10.12.17.101 | depostsolo[.]biz:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 4661862 bytes |
| 02:31:56 | payload-delivery | 10.12.17.101 | depostsolo[.]biz:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 17177209 bytes |
| 02:32:00 | dns-resolution | 10.12.17.101 | geo[.]netsupportsoftware[.]com | A query -> NOERROR [104.26.0.231, 104.26.1.231, 172.67.68.212] |
| 02:32:00 | c2-check-in | 10.12.17.101 | 194[.]180[.]191[.]64:443 | undecoded TCP session, port 443 with no TLS handshake, held open 1564s, 7297 bytes out / 522 bytes in |
| 02:32:00 | c2-check-in | 10.12.17.101 | 194[.]180[.]191[.]64:443 | 27 keepalive check-ins every ~60s (jitter 0%, score 89.7) |


## Indicators

Defanged. Machine-readable copies are in `output/2024-12-17-netsupport-rat/iocs.json`.

**Domains**

- `banks-canada[.]com` -> 34[.]42[.]173[.]126
- `depostsolo[.]biz` -> 185[.]33[.]84[.]25
- `taktlat[.]xyz` -> 185[.]33[.]84[.]25
- `geo[.]netsupportsoftware[.]com` -> 104[.]26[.]0[.]231, 104[.]26[.]1[.]231, 172[.]67[.]68[.]212

**Addresses**

- `34[.]42[.]173[.]126` ports 443 (tls)
- `185[.]33[.]84[.]25` ports 443 (tls)
- `104[.]26[.]0[.]231` ports 80 (http)
- `194[.]180[.]191[.]64` ports 443 (beacon)

## Cross-check against the published IOC list

The capture ships with an analyst-written indicator list. Comparing it with what the parsers recovered independently is this project's accuracy control.

| Indicator type | Published | Recovered | Recall |
|---|---|---|---|
| domains | 7 | 3 | 43% |
| ips | 1 | 1 | 100% |


Present in the published list but not recovered from the capture (these are typically file hashes, sandbox-only artifacts, or names listed as context rather than contacted):

`infosec[.]exchange`, `tactlat[.]xyz`, `threatfox[.]abuse[.]ch`, `www[.]threatdown[.]com`

## Detection opportunities

Rules generated from this case are in [../detections/](../detections/); the rationale for each is in [detection-opportunities.md](detection-opportunities.md).
