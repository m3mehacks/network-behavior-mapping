# 2024-06-25-latrodectus

**Family:** Latrodectus  
**Source:** https://www.malware-traffic-analysis.net/2024/06/25/index.html  
**Capture:** 2024-06-25-Latrodectus-infection-with-BackConnect-and-Keyhole-VNC.pcap  
**Window:** 2024-06-25T18:31:03.734Z to 2024-06-25T20:02:53.915Z (92 minutes)

Loader infection with BackConnect and Keyhole VNC, steady C2 beaconing.

Parsed 36,247 packets into 413 flows, yielding 217 DNS events, 11 HTTP transactions, 250 TLS handshakes and 9 beacon candidates.

## Beaconing cadence

| Score | Destination | Port | Kind | Check-ins | Interval | Jitter | Cadence |
|---|---|---|---|---|---|---|---|
| 84.4 (strong) | 64[.]7[.]198[.]158 | 443 | keepalive | 22 | 61s | 1.1% | 10-300s |
| 76.0 (likely) | client[.]wns[.]windows[.]com | 443 | keepalive | 14 | 245s | 0.0% | 10-300s |
| 71.3 (likely) | garunt[.]biz | 443 | connection | 41 | 113s | 48.6% | 10-300s |
| 70.1 (likely) | bibidj[.]biz | 443 | connection | 47 | 91s | 49.6% | 10-300s |
| 66.0 (likely) | barsman[.]biz | 443 | connection | 42 | 88s | 58.0% | 10-300s |
| 58.3 (likely) | ecs[.]office[.]com | 443 | connection | 7 | 300s | 37.9% | 5-60min |
| 42.7 (weak) | www[.]msn[.]com | 443 | connection | 5 | 766s | 50.9% | 5-60min |
| 38.3 (weak) | www[.]bing[.]com | 443 | keepalive | 10 | 2s | 57.7% | sub-10s |
| 8.3 (weak) | meakdgahup[.]com | 443 | connection | 5 | 281s | 98.5% | 10-300s |


The most regular channel is 64[.]7[.]198[.]158 on port 443: 22 events at a median of 61 seconds with 1.1% jitter, sustained over 21m28s.

## DNS and C2 domains

| Domain | Lookups | First seen | Resolved to | Response |
|---|---|---|---|---|
| bibidj[.]biz | 6 | 18:31:07 | 74[.]119[.]194[.]126 | NOERROR |
| x1[.]c[.]lencr[.]org | 2 | 18:31:08 | 173[.]222[.]253[.]27 | NOERROR |
| r11[.]o[.]lencr[.]org | 1 | 18:31:08 | 23[.]47[.]52[.]114, 23[.]47[.]52[.]116 | NOERROR |
| barsman[.]biz | 4 | 18:32:04 | 94[.]232[.]249[.]102 | NOERROR |
| r10[.]o[.]lencr[.]org | 3 | 18:32:04 | 23[.]47[.]52[.]114, 23[.]47[.]52[.]116, 23[.]47[.]52[.]120 | NOERROR |
| wpad[.]localdomain | 75 | 18:32:06 | - | - |
| finjuiceer[.]com | 2 | 18:34:30 | 184[.]174[.]96[.]179 | NOERROR |
| garunt[.]biz | 6 | 18:34:30 | 94[.]232[.]249[.]103 | NOERROR |
| windows[.]msn[.]com | 5 | 18:38:58 | 204[.]79[.]197[.]203 | NOERROR |
| assets[.]msn[.]com | 6 | 18:40:57 | 23[.]11[.]231[.]163, 23[.]11[.]231[.]184, 23[.]11[.]231[.]154, 23[.]11[.]231[.]152, 23[.]11[.]231[.]179, 23[.]11[.]231[.]168, 23[.]11[.]231[.]160, 23[.]11[.]231[.]171, 23[.]11[.]231[.]170, 23[.]53[.]13[.]197, 23[.]53[.]13[.]206, 23[.]53[.]13[.]208, 23[.]53[.]13[.]207, 23[.]11[.]231[.]178, 23[.]11[.]231[.]155, 23[.]11[.]231[.]176, 23[.]11[.]231[.]192, 23[.]11[.]231[.]193, 23[.]45[.]235[.]203, 23[.]45[.]235[.]114, 23[.]45[.]235[.]163, 23[.]45[.]235[.]201, 23[.]45[.]235[.]186, 23[.]45[.]235[.]184, 23[.]45[.]235[.]96, 23[.]45[.]235[.]168, 23[.]45[.]235[.]161 | NOERROR |
| www[.]msn[.]com | 2 | 18:40:59 | 204[.]79[.]197[.]203 | NOERROR |
| img-s-msn-com[.]akamaized[.]net | 3 | 18:41:01 | 23[.]36[.]217[.]179, 23[.]36[.]217[.]194, 23[.]196[.]11[.]29, 23[.]196[.]11[.]61, 23[.]196[.]11[.]15 | NOERROR |
| fp[.]msedge[.]net | 1 | 18:42:52 | 204[.]79[.]197[.]222 | NOERROR |
| k-ring[.]msedge[.]net | 1 | 18:42:55 | 13[.]107[.]18[.]254 | NOERROR |
| teams-ring[.]msedge[.]net | 1 | 18:42:56 | 52[.]113[.]196[.]254 | NOERROR |


_25 further domains in `output/2024-06-25-latrodectus/dns.csv`._

## HTTP endpoints

| Time | Method | Endpoint | Status | Response | Body |
|---|---|---|---|---|---|
| 18:31:03 | GET | 85[.]208[.]108[.]30/neuro[.]msi | 200 | 1047702 B | ole-compound |
| 18:31:08 | GET | x1[.]c[.]lencr[.]org/ | 200 | 717 B | - |
| 18:31:08 | GET | r11[.]o[.]lencr[.]org/MFMwUTBPME0wSzAJBgUrDgMCGgUABBQaUrm0WeTDM5ghfoZt | 200 | 504 B | - |
| 18:32:05 | GET | r10[.]o[.]lencr[.]org/MFMwUTBPME0wSzAJBgUrDgMCGgUABBRpD%2BQVZ%2B1vf7U0 | 200 | 504 B | - |
| 18:34:31 | GET | r10[.]o[.]lencr[.]org/MFMwUTBPME0wSzAJBgUrDgMCGgUABBRpD%2BQVZ%2B1vf7U0 | 200 | 504 B | - |
| 18:37:27 | GET | ocsp[.]digicert[.]com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBSAUQYBMq2awn1Rh6Do | 200 | 471 B | - |
| 18:37:56 | GET | ocsp[.]digicert[.]com/MFEwTzBNMEswSTAJBgUrDgMCGgUABBQ50otx%2Fh0Ztl%2Bz | 200 | 471 B | - |
| 19:23:11 | GET | ctldl[.]windowsupdate[.]com/msdownload/update/v3/static/trustedr/en/di | 304 | 202 B | - |
| 19:23:11 | GET | ctldl[.]windowsupdate[.]com/msdownload/update/v3/static/trustedr/en/pi | - | 0 B | - |
| 19:34:00 | GET | x1[.]c[.]lencr[.]org/ | 304 | 0 B | - |
| 19:36:02 | GET | ctldl[.]windowsupdate[.]com/msdownload/update/v3/static/trustedr/en/au | 304 | 0 B | - |


Unusual user agents:

- `Microsoft-CryptoAPI/10.0` (5 requests)
- `Windows Installer` (1 requests)

## TLS fingerprints

| Destination | Port | Version | JA4 | JA4S | JA3 |
|---|---|---|---|---|---|
| bibidj[.]biz | 443 | TLS 1.3 | t13d201100_2b729b4bf6f3_9e7b989ebec8 | t130200_1302_a56c5b993250 | 3c293bdf2a25c075... |
| barsman[.]biz | 443 | TLS 1.3 | t13d201100_2b729b4bf6f3_9e7b989ebec8 | t130200_1302_a56c5b993250 | 3c293bdf2a25c075... |
| bibidj[.]biz | 443 | TLS 1.3 | t13d201200_2b729b4bf6f3_2e4f304f1f45 | t130300_1302_0ee26285a86f | 5919f6108f098e14... |
| officeclient[.]microsoft[.]com | 443 | TLS 1.2 | t12d180800_4b22cbed5bed_7af1ed941c26 | t120300_c030_09f674154ab3 | 258a5a1e95b8a911... |
| ecs[.]office[.]com | 443 | TLS 1.2 | t12d180800_4b22cbed5bed_7af1ed941c26 | t120500_c030_fc2f84b53bab | 258a5a1e95b8a911... |
| login[.]live[.]com | 443 | TLS 1.3 | t13d2012h2_2b729b4bf6f3_9e7b989ebec8 | t120400_c030_4e8089b08790 | 65005c9d9ae0f0eb... |
| mobile[.]events[.]data[.]microsoft[.]com | 443 | TLS 1.3 | t13d201200_2b729b4bf6f3_2e4f304f1f45 | t130200_1302_a56c5b993250 | 5919f6108f098e14... |
| finjuiceer[.]com | 443 | TLS 1.3 | t13d201100_2b729b4bf6f3_9e7b989ebec8 | t120400_c030_536640354c12 | 3c293bdf2a25c075... |
| garunt[.]biz | 443 | TLS 1.3 | t13d201100_2b729b4bf6f3_9e7b989ebec8 | t130200_1302_a56c5b993250 | 3c293bdf2a25c075... |
| ecs[.]office[.]com | 443 | TLS 1.3 | t13d201200_2b729b4bf6f3_2e4f304f1f45 | t130200_1302_a56c5b993250 | 5919f6108f098e14... |
| barsman[.]biz | 443 | TLS 1.3 | t13d201200_2b729b4bf6f3_2e4f304f1f45 | t130300_1302_0ee26285a86f | 5919f6108f098e14... |
| v10[.]events[.]data[.]microsoft[.]com | 443 | TLS 1.2 | t12d1809h2_4b22cbed5bed_7af1ed941c26 | t1204h2_c030_b252f78b95f6 | 091f51a7a1c3a450... |
| storecatalogrevocation[.]storequality[.]microsoft[.]com | 443 | TLS 1.3 | t13d2012h2_2b729b4bf6f3_9e7b989ebec8 | t1205h1_c030_a6bc814040bb | 65005c9d9ae0f0eb... |
| assets[.]msn[.]com | 443 | TLS 1.3 | t13d2013h2_2b729b4bf6f3_2e4f304f1f45 | t130300_1302_0ee26285a86f | 46f5131e766d248d... |
| www[.]msn[.]com | 443 | TLS 1.3 | t13d1516h2_8daaf6152771_02713d6af862 | t130200_1302_a56c5b993250 | d6b969a284d48bd3... |


## Timeline of observed activity

| Time | Phase | Source | Destination | Observation |
|---|---|---|---|---|
| 18:31:03 | initial-access | 10.6.25.101 | 85[.]208[.]108[.]30:80 | GET /neuro.msi -> 200, 1047702 bytes, body=ole-compound |
| 18:31:07 | dns-resolution | 10.6.25.101 | bibidj[.]biz | A query -> NOERROR [74.119.194.126] |
| 18:31:08 | c2-check-in | 10.6.25.101 | bibidj[.]biz:443 | 47 connection check-ins every ~91s (jitter 50%, score 70.1) |
| 18:31:08 | c2-check-in | 10.6.25.101 | bibidj[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3906 bytes |
| 18:31:08 | dns-resolution | 10.6.25.101 | x1[.]c[.]lencr[.]org | A query -> NOERROR [173.222.253.27] |
| 18:31:08 | initial-access | 10.6.25.101 | x1[.]c[.]lencr[.]org:80 | GET / -> 200, 717 bytes |
| 18:31:08 | dns-resolution | 10.6.25.101 | r11[.]o[.]lencr[.]org | A query -> NOERROR [23.47.52.114, 23.47.52.116] |
| 18:31:08 | initial-access | 10.6.25.101 | r11[.]o[.]lencr[.]org:80 | GET /MFMwUTBPME0wSzAJBgUrDgMCGgUABBQaUrm0WeTDM5ghfoZtS72KO9ZnzgQUCLkRO6XQhRi06g%2BgrZ%2BGHo78OCcCEgO2f8Ex4ofFC |
| 18:31:09 | payload-delivery | 10.6.25.101 | bibidj[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 200153 bytes |
| 18:32:04 | dns-resolution | 10.6.25.101 | barsman[.]biz | A query -> NOERROR [94.232.249.102] |
| 18:32:04 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | 42 connection check-ins every ~88s (jitter 58%, score 66.0) |
| 18:32:04 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3886 bytes |
| 18:32:04 | dns-resolution | 10.6.25.101 | r10[.]o[.]lencr[.]org | A query -> NOERROR [23.47.52.114, 23.47.52.116] |
| 18:32:06 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:32:06 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:32:07 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:32:07 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:32:09 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:32:09 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:32:13 | dns-resolution | 10.6.25.101 | r10[.]o[.]lencr[.]org | A query -> NOERROR [23.47.52.116, 23.47.52.114] |
| 18:33:04 | c2-check-in | 10.6.25.101 | bibidj[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 717 bytes |
| 18:33:53 | c2-check-in | 10.6.25.101 | ecs[.]office[.]com:443 | 7 connection check-ins every ~301s (jitter 38%, score 58.3) |
| 18:33:53 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3854 bytes |
| 18:33:53 | c2-check-in | 10.6.25.101 | ecs[.]office[.]com:443 | TLS 1.2 handshake, JA3 258a5a1e95b8..., JA4 t12d180800_4b22cbed5bed_7af1ed941c26, received 7077 bytes |
| 18:34:30 | dns-resolution | 10.6.25.101 | finjuiceer[.]com | A query -> NOERROR [184.174.96.179] |
| 18:34:30 | dns-resolution | 10.6.25.101 | garunt[.]biz | A query -> NOERROR [94.232.249.103] |
| 18:34:31 | c2-check-in | 10.6.25.101 | garunt[.]biz:443 | 41 connection check-ins every ~113s (jitter 49%, score 71.3) |
| 18:34:31 | c2-check-in | 10.6.25.101 | garunt[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3852 bytes |
| 18:34:31 | dns-resolution | 10.6.25.101 | r10[.]o[.]lencr[.]org | A query -> NOERROR [23.47.52.114, 23.47.52.120, 23.47.52.116] |
| 18:35:00 | c2-check-in | 10.6.25.101 | ecs[.]office[.]com:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 7380 bytes |
| 18:35:20 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 717 bytes |
| 18:35:48 | c2-check-in | 10.6.25.101 | bibidj[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 717 bytes |
| 18:36:49 | c2-check-in | 10.6.25.101 | bibidj[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3853 bytes |
| 18:37:35 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 733 bytes |
| 18:38:18 | c2-check-in | 10.6.25.101 | bibidj[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 717 bytes |
| 18:38:58 | dns-resolution | 10.6.25.101 | windows[.]msn[.]com | A query -> NOERROR [204.79.197.203] |
| 18:39:00 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3830 bytes |
| 18:39:37 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 733 bytes |
| 18:40:03 | c2-check-in | 10.6.25.101 | barsman[.]biz:443 | TLS 1.3 handshake, JA3 5919f6108f09..., JA4 t13d201200_2b729b4bf6f3_2e4f304f1f45, received 733 bytes |
| 18:40:52 | c2-check-in | 10.6.25.101 | garunt[.]biz:443 | TLS 1.3 handshake, JA3 3c293bdf2a25..., JA4 t13d201100_2b729b4bf6f3_9e7b989ebec8, received 3852 bytes |
| 18:40:57 | dns-resolution | 10.6.25.101 | assets[.]msn[.]com | A query -> NOERROR [23.11.231.163, 23.11.231.184, 23.11.231.154, 23.11.231.152, 23.11.231.179, 23.11.231.168,  |
| 18:40:58 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:40:59 | dns-resolution | 10.6.25.101 | wpad[.]localdomain | A query -> no response |
| 18:40:59 | dns-resolution | 10.6.25.101 | www[.]msn[.]com | A query -> NOERROR [204.79.197.203] |
| 18:41:01 | dns-resolution | 10.6.25.101 | img-s-msn-com[.]akamaized[.]net | A query -> NOERROR [23.36.217.179, 23.36.217.194] |


_271 further notable events in `output/2024-06-25-latrodectus/timeline.csv`._

## Indicators

Defanged. Machine-readable copies are in `output/2024-06-25-latrodectus/iocs.json`.

**Domains**

- `85[.]208[.]108[.]30` -> 85[.]208[.]108[.]30
- `bibidj[.]biz` -> 74[.]119[.]194[.]126
- `x1[.]c[.]lencr[.]org` -> 173[.]222[.]253[.]27
- `r11[.]o[.]lencr[.]org` -> 23[.]47[.]52[.]114, 23[.]47[.]52[.]116
- `barsman[.]biz` -> 94[.]232[.]249[.]102
- `r10[.]o[.]lencr[.]org` -> 23[.]47[.]52[.]114, 23[.]47[.]52[.]116, 23[.]47[.]52[.]120
- `finjuiceer[.]com` -> 184[.]174[.]96[.]179
- `garunt[.]biz` -> 94[.]232[.]249[.]103
- `windows[.]msn[.]com` -> 204[.]79[.]197[.]203
- `assets[.]msn[.]com` -> 23[.]11[.]231[.]163, 23[.]11[.]231[.]184, 23[.]11[.]231[.]154, 23[.]11[.]231[.]152, 23[.]11[.]231[.]179, 23[.]11[.]231[.]168, 23[.]11[.]231[.]160, 23[.]11[.]231[.]171, 23[.]11[.]231[.]170, 23[.]53[.]13[.]197, 23[.]53[.]13[.]206, 23[.]53[.]13[.]208, 23[.]53[.]13[.]207, 23[.]11[.]231[.]178, 23[.]11[.]231[.]155, 23[.]11[.]231[.]176, 23[.]11[.]231[.]192, 23[.]11[.]231[.]193, 23[.]45[.]235[.]203, 23[.]45[.]235[.]114, 23[.]45[.]235[.]163, 23[.]45[.]235[.]201, 23[.]45[.]235[.]186, 23[.]45[.]235[.]184, 23[.]45[.]235[.]96, 23[.]45[.]235[.]168, 23[.]45[.]235[.]161
- `www[.]msn[.]com` -> 204[.]79[.]197[.]203
- `img-s-msn-com[.]akamaized[.]net` -> 23[.]36[.]217[.]179, 23[.]36[.]217[.]194, 23[.]196[.]11[.]29, 23[.]196[.]11[.]61, 23[.]196[.]11[.]15
- `fp[.]msedge[.]net` -> 204[.]79[.]197[.]222
- `k-ring[.]msedge[.]net` -> 13[.]107[.]18[.]254
- `teams-ring[.]msedge[.]net` -> 52[.]113[.]196[.]254

**Addresses**

- `85[.]208[.]108[.]30` ports 80 (http)
- `74[.]119[.]194[.]126` ports 443 (tls, beacon)
- `173[.]222[.]253[.]27` ports 80 (http)
- `23[.]47[.]52[.]114` ports 80 (http)
- `94[.]232[.]249[.]102` ports 443 (tls, beacon)
- `52[.]113[.]194[.]132` ports 443 (beacon)
- `184[.]174[.]96[.]179` ports 443 (tls)
- `94[.]232[.]249[.]103` ports 443 (tls, beacon)
- `23[.]11[.]231[.]163` ports 443 (tls)
- `204[.]79[.]197[.]203` ports 443 (tls)
- `23[.]196[.]11[.]29` ports 443 (tls)
- `204[.]79[.]197[.]222` ports 443 (tls)
- `13[.]107[.]18[.]254` ports 443 (tls)
- `52[.]113[.]196[.]254` ports 443 (tls)
- `23[.]11[.]231[.]187` ports 443 (tls)

## Cross-check against the published IOC list

The capture ships with an analyst-written indicator list. Comparing it with what the parsers recovered independently is this project's accuracy control.

| Indicator type | Published | Recovered | Recall |
|---|---|---|---|
| domains | 11 | 6 | 55% |
| ips | 10 | 8 | 80% |


Present in the published list but not recovered from the capture (these are typically file hashes, sandbox-only artifacts, or names listed as context rather than contacted):

`barsen[.]monster`, `firebasestorage[.]googleapis[.]com`, `kkk17-427021[.]appspot[.]com`, `kurvabbr[.]pw`, `namo-426715[.]appspot[.]com`, `193[.]32[.]177[.]192`, `85[.]208[.]108[.]63`

## Detection opportunities

Rules generated from this case are in [../detections/](../detections/); the rationale for each is in [detection-opportunities.md](detection-opportunities.md).
