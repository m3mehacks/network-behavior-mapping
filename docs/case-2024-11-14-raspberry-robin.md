# 2024-11-14-raspberry-robin

**Family:** Raspberry Robin  
**Source:** https://www.malware-traffic-analysis.net/2024/11/14/index.html  
**Capture:** 2024-11-14-Raspberry-Robin-infection-traffic.pcap  
**Window:** 2024-11-14T21:13:45.961Z to 2024-11-14T23:59:52.452Z (166 minutes)

Infection using a WebDAV server, unusual protocol and port profile.

Parsed 91,481 packets into 51 flows, yielding 2 DNS events, 0 HTTP transactions, 46 TLS handshakes and 16 beacon candidates.

## Beaconing cadence

| Score | Destination | Port | Kind | Check-ins | Interval | Jitter | Cadence |
|---|---|---|---|---|---|---|---|
| 88.1 (strong) | www[.]sdeq3iozavf[.]com | 9001 | keepalive | 43 | 1s | 4.4% | sub-10s |
| 77.8 (likely) | www[.]hspyh52[.]com | 9001 | keepalive | 20 | 7s | 20.0% | sub-10s |
| 74.6 (likely) | www[.]sdeq3iozavf[.]com | 9001 | keepalive | 14 | 1s | 2.5% | sub-10s |
| 70.8 (likely) | www[.]hspyh52[.]com | 9001 | keepalive | 31 | 1s | 27.5% | sub-10s |
| 68.8 (likely) | www[.]hspyh52[.]com | 9001 | keepalive | 10 | 1s | 5.0% | sub-10s |
| 64.8 (likely) | www[.]hspyh52[.]com | 9001 | keepalive | 25 | 2s | 50.2% | sub-10s |
| 59.6 (likely) | www[.]sdeq3iozavf[.]com | 9001 | keepalive | 293 | 7s | 46.1% | sub-10s |
| 58.6 (likely) | www[.]hspyh52[.]com | 9001 | connection | 8 | 1068s | 15.3% | 5-60min |
| 56.7 (likely) | www[.]sdeq3iozavf[.]com | 9001 | connection | 8 | 1054s | 18.7% | 5-60min |
| 56.0 (likely) | www[.]sdeq3iozavf[.]com | 9001 | keepalive | 25 | 2s | 56.0% | sub-10s |
| 54.5 (weak) | 2z[.]si | 443 | connection | 11 | 3s | 45.9% | sub-10s |
| 53.5 (weak) | www[.]sdeq3iozavf[.]com | 9001 | keepalive | 17 | 8s | 55.7% | sub-10s |
| 53.2 (weak) | www[.]hspyh52[.]com | 9001 | keepalive | 244 | 7s | 57.9% | sub-10s |
| 50.5 (weak) | www[.]hspyh52[.]com | 9001 | keepalive | 19 | 4s | 72.0% | sub-10s |
| 50.5 (weak) | www[.]hspyh52[.]com | 9001 | keepalive | 19 | 5s | 60.0% | sub-10s |


The most regular channel is www[.]sdeq3iozavf[.]com on port 9001: 43 events at a median of 1 seconds with 4.4% jitter, sustained over 2m04s.

That cadence is below ten seconds, which is the rhythm of transport keepalive or padding rather than a command and control check-in. Tor behaves this way, and it outranks genuine C2 on regularity alone.

The highest-scoring channel in the check-in range is www[.]hspyh52[.]com on port 9001, 8 events every 1068 seconds at 15.3% jitter.

## DNS and C2 domains

| Domain | Lookups | First seen | Resolved to | Response |
|---|---|---|---|---|
| 735dba63[.]bright-witted[.]skin | 1 | 21:13:45 | 172[.]67[.]153[.]95, 104[.]21[.]88[.]209 | NOERROR |
| 2z[.]si | 1 | 21:13:50 | 194[.]165[.]16[.]82 | NOERROR |


## HTTP endpoints

_None observed._


## TLS fingerprints

| Destination | Port | Version | JA4 | JA4S | JA3 |
|---|---|---|---|---|---|
| 735dba63[.]bright-witted[.]skin | 443 | TLS 1.2 | t12d180700_4b22cbed5bed_2dae41c691ec | t120500_c02b_b508675693ed | 6a5d235ee78c6aed... |
| 2z[.]si | 443 | TLS 1.2 | t12d180700_4b22cbed5bed_2dae41c691ec | t120400_c030_1b122d51bd39 | 6a5d235ee78c6aed... |
| 185[.]141[.]56[.]26 | 443 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 107[.]189[.]29[.]184 | 443 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 139[.]99[.]134[.]168 | 80 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 194[.]26[.]192[.]77 | 110 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 139[.]99[.]170[.]35 | 443 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 107[.]189[.]8[.]65 | 443 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 62[.]141[.]48[.]175 | 444 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| 188[.]245[.]194[.]221 | 443 | TLS 1.2 | t12i180600_4b22cbed5bed_2dae41c691ec | t120300_c030_460f64128655 | 43016d7f7f9336b1... |
| www[.]vfnbzcosotyp[.]com | 443 | TLS 1.2 | t12d140600_afab075e6c91_a1e935682795 | t120200_c030_344b4dce5a52 | 83d60721ecc42389... |
| www[.]hspyh52[.]com | 9001 | TLS 1.2 | t12d140600_afab075e6c91_a1e935682795 | t120200_c030_344b4dce5a52 | 83d60721ecc42389... |
| www[.]sdeq3iozavf[.]com | 9001 | TLS 1.2 | t12d140600_afab075e6c91_a1e935682795 | t120200_c030_344b4dce5a52 | 83d60721ecc42389... |
| www[.]u7tlc2waowd[.]com | 9001 | TLS 1.2 | t12d140600_afab075e6c91_a1e935682795 | t120200_c030_344b4dce5a52 | 83d60721ecc42389... |
| www[.]43oy4koz65rj756yfmnk7wtip[.]com | 9001 | TLS 1.2 | t12d140600_afab075e6c91_a1e935682795 | t120200_c030_344b4dce5a52 | 83d60721ecc42389... |


## Timeline of observed activity

| Time | Phase | Source | Destination | Observation |
|---|---|---|---|---|
| 21:13:45 | dns-resolution | 10.0.0.101 | 735dba63[.]bright-witted[.]skin | A query -> NOERROR [172.67.153.95, 104.21.88.209] |
| 21:13:46 | payload-delivery | 10.0.0.101 | 735dba63[.]bright-witted[.]skin:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 5989368 bytes |
| 21:13:50 | dns-resolution | 10.0.0.101 | 2z[.]si | A query -> NOERROR [194.165.16.82] |
| 21:13:58 | payload-delivery | 10.0.0.101 | 2z[.]si:443 | TLS 1.2 handshake, JA3 6a5d235ee78c..., JA4 t12d180700_4b22cbed5bed_2dae41c691ec, received 2701578 bytes |
| 21:28:49 | payload-delivery | 10.0.0.101 | 185[.]141[.]56[.]26:443 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, no SNI, received 752936 byte |
| 21:28:53 | payload-delivery | 10.0.0.101 | 107[.]189[.]29[.]184:443 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, no SNI, received 10745911 by |
| 21:29:08 | payload-delivery | 10.0.0.101 | 139[.]99[.]134[.]168:80 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, TLS on non-standard port 80, |
| 21:29:28 | payload-delivery | 10.0.0.101 | 194[.]26[.]192[.]77:110 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, TLS on non-standard port 110 |
| 21:29:35 | post-infection | 10.0.0.101 | 139[.]99[.]170[.]35:443 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, no SNI, received 47252 bytes |
| 21:29:39 | post-infection | 10.0.0.101 | 107[.]189[.]8[.]65:443 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, no SNI, received 4738 bytes |
| 21:29:53 | payload-delivery | 10.0.0.101 | 62[.]141[.]48[.]175:444 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, TLS on non-standard port 444 |
| 21:29:56 | post-infection | 10.0.0.101 | 188[.]245[.]194[.]221:443 | TLS 1.2 handshake, JA3 43016d7f7f93..., JA4 t12i180600_4b22cbed5bed_2dae41c691ec, no SNI, received 4738 bytes |
| 21:33:04 | payload-delivery | 10.0.0.101 | www[.]vfnbzcosotyp[.]com:443 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, received 770787 bytes |
| 21:33:07 | c2-check-in | 10.0.0.101 | www[.]sdeq3iozavf[.]com:9001 | 8 connection check-ins every ~1054s (jitter 19%, score 56.7) |
| 21:33:07 | c2-check-in | 10.0.0.101 | www[.]hspyh52[.]com:9001 | 8 connection check-ins every ~1068s (jitter 15%, score 58.6) |
| 21:33:07 | c2-check-in | 10.0.0.101 | www[.]hspyh52[.]com:9001 | 10 keepalive check-ins every ~1s (jitter 5%, score 68.8) |
| 21:33:07 | c2-check-in | 10.0.0.101 | www[.]hspyh52[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 21:33:07 | c2-check-in | 10.0.0.101 | www[.]sdeq3iozavf[.]com:9001 | 14 keepalive check-ins every ~1s (jitter 2%, score 74.6) |
| 21:33:07 | c2-check-in | 10.0.0.101 | www[.]sdeq3iozavf[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 21:33:21 | c2-check-in | 10.0.0.101 | www[.]u7tlc2waowd[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 21:33:23 | c2-check-in | 10.0.0.101 | www[.]sdeq3iozavf[.]com:9001 | 293 keepalive check-ins every ~7s (jitter 46%, score 59.6) |
| 21:33:23 | c2-check-in | 10.0.0.101 | www[.]43oy4koz65rj756yfmnk7wtip[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 22:25:05 | post-infection | 10.0.0.101 | www[.]eag3z5qjlh[.]com:28003 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 280 |
| 22:25:07 | c2-check-in | 10.0.0.101 | www[.]h3vwdoskpr5eqyjrs[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 22:25:07 | c2-check-in | 10.0.0.101 | www[.]hspyh52[.]com:9001 | 20 keepalive check-ins every ~7s (jitter 20%, score 77.8) |
| 22:25:07 | c2-check-in | 10.0.0.101 | www[.]on2x3gnnpupifbfdp[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 22:33:29 | c2-check-in | 10.0.0.101 | www[.]cssfd5p5cezgcr2yw[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 22:33:35 | c2-check-in | 10.0.0.101 | www[.]bpgluls4z73vw[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 22:51:23 | c2-check-in | 10.0.0.101 | www[.]hspyh52[.]com:9001 | 25 keepalive check-ins every ~2s (jitter 50%, score 64.8) |
| 22:51:23 | c2-check-in | 10.0.0.101 | www[.]f4lbnxd5dgegwmnboith34[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 22:51:30 | c2-check-in | 10.0.0.101 | www[.]y47v7333l46da5v7vb[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 23:11:55 | c2-check-in | 10.0.0.101 | www[.]hspyh52[.]com:9001 | 31 keepalive check-ins every ~1s (jitter 28%, score 70.8) |
| 23:11:55 | c2-check-in | 10.0.0.101 | www[.]q7xi3oldut[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 23:12:20 | c2-check-in | 10.0.0.101 | www[.]ixolgnuujpiks6skeu[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 23:29:54 | c2-check-in | 10.0.0.101 | www[.]sdeq3iozavf[.]com:9001 | 43 keepalive check-ins every ~1s (jitter 4%, score 88.1) |
| 23:29:54 | c2-check-in | 10.0.0.101 | www[.]u5opnofx[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 23:30:09 | c2-check-in | 10.0.0.101 | www[.]46vwtg[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 23:37:30 | post-infection | 10.0.0.101 | 37[.]1[.]195[.]110:443 | undecoded TCP session, port 443 with no TLS handshake, 368 bytes out / 5012 bytes in |
| 23:42:15 | post-infection | 10.0.0.101 | 38[.]180[.]208[.]173:443 | undecoded TCP session, port 443 with no TLS handshake, held open 1057s, 460 bytes out / 40022 bytes in |
| 23:47:04 | c2-check-in | 10.0.0.101 | www[.]sdeq3iozavf[.]com:9001 | 25 keepalive check-ins every ~2s (jitter 56%, score 56.0) |
| 23:47:04 | c2-check-in | 10.0.0.101 | www[.]vn7hq5cssukfmtpltom2d[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |
| 23:47:10 | c2-check-in | 10.0.0.101 | www[.]stkrrkb3mvqt[.]com:9001 | TLS 1.2 handshake, JA3 83d60721ecc4..., JA4 t12d140600_afab075e6c91_a1e935682795, TLS on non-standard port 900 |


## Indicators

Defanged. Machine-readable copies are in `output/2024-11-14-raspberry-robin/iocs.json`.

**Domains**

- `735dba63[.]bright-witted[.]skin` -> 172[.]67[.]153[.]95, 104[.]21[.]88[.]209
- `2z[.]si` -> 194[.]165[.]16[.]82
- `www[.]vfnbzcosotyp[.]com` -> 162[.]251[.]116[.]50
- `www[.]hspyh52[.]com` -> 37[.]114[.]55[.]122
- `www[.]sdeq3iozavf[.]com` -> 193[.]219[.]97[.]25
- `www[.]u7tlc2waowd[.]com` -> 37[.]114[.]55[.]122
- `www[.]43oy4koz65rj756yfmnk7wtip[.]com` -> 193[.]219[.]97[.]25
- `www[.]eag3z5qjlh[.]com` -> 213[.]255[.]226[.]243
- `www[.]h3vwdoskpr5eqyjrs[.]com` -> 193[.]219[.]97[.]25
- `www[.]on2x3gnnpupifbfdp[.]com` -> 37[.]114[.]55[.]122
- `www[.]cssfd5p5cezgcr2yw[.]com` -> 193[.]219[.]97[.]25
- `www[.]bpgluls4z73vw[.]com` -> 37[.]114[.]55[.]122
- `www[.]f4lbnxd5dgegwmnboith34[.]com` -> 37[.]114[.]55[.]122
- `www[.]y47v7333l46da5v7vb[.]com` -> 193[.]219[.]97[.]25
- `www[.]q7xi3oldut[.]com` -> 37[.]114[.]55[.]122

**Addresses**

- `172[.]67[.]153[.]95` ports 443 (tls)
- `194[.]165[.]16[.]82` ports 443 (tls)
- `185[.]141[.]56[.]26` ports 443 (tls)
- `107[.]189[.]29[.]184` ports 443 (tls)
- `139[.]99[.]134[.]168` ports 80 (tls)
- `194[.]26[.]192[.]77` ports 110 (tls)
- `139[.]99[.]170[.]35` ports 443 (tls)
- `107[.]189[.]8[.]65` ports 443 (tls)
- `62[.]141[.]48[.]175` ports 444 (tls)
- `188[.]245[.]194[.]221` ports 443 (tls)
- `162[.]251[.]116[.]50` ports 443 (tls)
- `37[.]114[.]55[.]122` ports 9001 (tls, beacon)
- `193[.]219[.]97[.]25` ports 9001 (tls, beacon)
- `213[.]255[.]226[.]243` ports 28003 (tls)

## Detection opportunities

Rules generated from this case are in [../detections/](../detections/); the rationale for each is in [detection-opportunities.md](detection-opportunities.md).
