# I2P Network Node Analysis

> Generated: 2026-06-27 08:42 UTC
> Data collected passively via i2pd floodfill nodes on the I2P main network (netId=2).
> RouterInfo files parsed with `quick_scan.py`, stored in SQLite (`i2p_nodes.db`).
> GeoIP: MaxMind GeoLite2-Country.

## 1. Overview

| Metric | Value |
|---|---|
| Known routers | **19,033** |
| Public (has IP) | **5,279**  (27.7%) |
| Firewalled / NAT | **13,754**  (72.3%) |
| Unique IP addresses | **5,041** |
| Floodfill routers | **88** |
| Reachable routers | **95** |

### Key findings

- **Only 5,279 routers (~27%) publish an IP address.** The remaining 13,754 (~73%) sit behind NAT or firewalls and are reachable only through SSU2 introducers.
- This is **by design** in I2P — not a scanning-coverage gap. Hidden routers do not include a `host=` field in their RouterInfo.

## 2. Public vs Hidden Nodes

### By version

| Version | Total | Public | Hidden | Public % |
|---|---|---|---|---|
| 0.9.68 | 9,427 | 1,075 | 8,352 | 11.4% |
| 0.9.69 | 3,627 | 1,945 | 1,682 | 53.6% |
| 0.9.67 | 1,752 | 587 | 1,165 | 33.5% |
| 0.9.61 | 1,386 | 411 | 975 | 29.7% |
| 0.9.65 | 714 | 267 | 447 | 37.4% |
| 0.9.64 | 666 | 275 | 391 | 41.3% |
| 0.9.57 | 431 | 270 | 161 | 62.6% |
| 0.9.66 | 372 | 163 | 209 | 43.8% |
| 0.9.60 | 121 | 24 | 97 | 19.8% |
| 0.9.62 | 110 | 45 | 65 | 40.9% |

*Interpretation*: v0.9.68 dominates (47% of all routers) but has the lowest public ratio (11%). Newer v0.9.69 has better reachability (55%).

### By transport protocol

| Protocol | Routers |
|---|---|
| NTCP2 + SSU2 | 5,112 |
| NTCP2 | 148 |
| SSU2 | 19 |

## 3. Geographic Distribution

*(Public-IP routers only; 4518 routers enriched with GeoIP)*

### By continent

| Continent | Routers | Share |
|---|---|---|
| Europe | 2,193 | 48.5% |
| North America | 1,341 | 29.7% |
| Asia | 647 | 14.3% |
| South America | 168 | 3.7% |
| Oceania | 117 | 2.6% |
| Africa | 52 | 1.2% |

### Top 20 countries

| Rank | Country | Routers | Share |
|---|---|---|---|
| 1 | US | 1,076 | 23.8% |
| 2 | RU | 526 | 11.6% |
| 3 | DE | 384 | 8.5% |
| 4 | NL | 207 | 4.6% |
| 5 | CA | 191 | 4.2% |
| 6 | FR | 144 | 3.2% |
| 7 | GB | 125 | 2.8% |
| 8 | AU | 102 | 2.3% |
| 9 | IR | 98 | 2.2% |
| 10 | FI | 95 | 2.1% |
| 11 | SE | 87 | 1.9% |
| 12 | CN | 81 | 1.8% |
| 13 | BR | 75 | 1.7% |
| 14 | IN | 70 | 1.5% |
| 15 | PL | 65 | 1.4% |
| 16 | UA | 59 | 1.3% |
| 17 | ES | 56 | 1.2% |
| 18 | TR | 53 | 1.2% |
| 19 | MX | 51 | 1.1% |
| 20 | ID | 46 | 1.0% |

### Full country list

| Country | Code | Routers | Share |
|---|---|---|---|
| US | US | 1,076 | 23.8% |
| RU | RU | 526 | 11.6% |
| DE | DE | 384 | 8.5% |
| NL | NL | 207 | 4.6% |
| CA | CA | 191 | 4.2% |
| FR | FR | 144 | 3.2% |
| GB | GB | 125 | 2.8% |
| AU | AU | 102 | 2.3% |
| IR | IR | 98 | 2.2% |
| FI | FI | 95 | 2.1% |
| SE | SE | 87 | 1.9% |
| CN | CN | 81 | 1.8% |
| BR | BR | 75 | 1.7% |
| IN | IN | 70 | 1.5% |
| PL | PL | 65 | 1.4% |
| UA | UA | 59 | 1.3% |
| ES | ES | 56 | 1.2% |
| TR | TR | 53 | 1.2% |
| MX | MX | 51 | 1.1% |
| ID | ID | 46 | 1.0% |
| SG | SG | 43 | 1.0% |
| JP | JP | 42 | 0.9% |
| CH | CH | 40 | 0.9% |
| AR | AR | 40 | 0.9% |
| IT | IT | 39 | 0.9% |
| KR | KR | 33 | 0.7% |
| CZ | CZ | 32 | 0.7% |
| AT | AT | 32 | 0.7% |
| VN | VN | 31 | 0.7% |
| RO | RO | 31 | 0.7% |
| MD | MD | 28 | 0.6% |
| PT | PT | 25 | 0.6% |
| LT | LT | 25 | 0.6% |
| IS | IS | 25 | 0.6% |
| CL | CL | 22 | 0.5% |
| HK | HK | 21 | 0.5% |
| HU | HU | 20 | 0.4% |
| SA | SA | 19 | 0.4% |
| BG | BG | 18 | 0.4% |
| AE | AE | 18 | 0.4% |
| ZA | ZA | 15 | 0.3% |
| TW | TW | 14 | 0.3% |
| RS | RS | 13 | 0.3% |
| NZ | NZ | 13 | 0.3% |
| NO | NO | 12 | 0.3% |
| MY | MY | 12 | 0.3% |
| EE | EE | 11 | 0.2% |
| KZ | KZ | 10 | 0.2% |
| GR | GR | 10 | 0.2% |
| EG | EG | 10 | 0.2% |
| BE | BE | 10 | 0.2% |
| BD | BD | 10 | 0.2% |
| LV | LV | 9 | 0.2% |
| IL | IL | 9 | 0.2% |
| CO | CO | 9 | 0.2% |
| TH | TH | 8 | 0.2% |
| HR | HR | 8 | 0.2% |
| DK | DK | 8 | 0.2% |
| BY | BY | 8 | 0.2% |
| DZ | DZ | 7 | 0.2% |
| SK | SK | 6 | 0.1% |
| SI | SI | 6 | 0.1% |
| SC | SC | 6 | 0.1% |
| PK | PK | 6 | 0.1% |
| TT | TT | 5 | 0.1% |
| PY | PY | 5 | 0.1% |
| PH | PH | 5 | 0.1% |
| MA | MA | 5 | 0.1% |
| LU | LU | 5 | 0.1% |
| IE | IE | 5 | 0.1% |
| EC | EC | 5 | 0.1% |
| AL | AL | 5 | 0.1% |
| VG | VG | 4 | 0.1% |
| PA | PA | 4 | 0.1% |
| BO | BO | 4 | 0.1% |
| AM | AM | 4 | 0.1% |
| UY | UY | 3 | 0.1% |
| RE | RE | 3 | 0.1% |
| MT | MT | 3 | 0.1% |
| MK | MK | 3 | 0.1% |
| LI | LI | 3 | 0.1% |
| BM | BM | 3 | 0.1% |
| VE | VE | 2 | 0.0% |
| TN | TN | 2 | 0.0% |
| PG | PG | 2 | 0.0% |
| PE | PE | 2 | 0.0% |
| OM | OM | 2 | 0.0% |
| MQ | MQ | 2 | 0.0% |
| MM | MM | 2 | 0.0% |
| GE | GE | 2 | 0.0% |
| CY | CY | 2 | 0.0% |
| BZ | BZ | 2 | 0.0% |
| UZ | UZ | 1 | 0.0% |
| TM | TM | 1 | 0.0% |
| NG | NG | 1 | 0.0% |
| MV | MV | 1 | 0.0% |
| MN | MN | 1 | 0.0% |
| MC | MC | 1 | 0.0% |
| LA | LA | 1 | 0.0% |
| KW | KW | 1 | 0.0% |
| KH | KH | 1 | 0.0% |
| KE | KE | 1 | 0.0% |
| JE | JE | 1 | 0.0% |
| GF | GF | 1 | 0.0% |
| DO | DO | 1 | 0.0% |
| CM | CM | 1 | 0.0% |
| BB | BB | 1 | 0.0% |
| BA | BA | 1 | 0.0% |
| AZ | AZ | 1 | 0.0% |
| AW | AW | 1 | 0.0% |
| AO | AO | 1 | 0.0% |

## 4. Infrastructure

### Bandwidth tiers

| Tier | Meaning | Routers |
|---|---|---|
| X | > 2048 KB/s | 76 |
| P | 256–2048 KB/s | 9 |
| O | 128–256 KB/s | 7 |
| L | 12–48 KB/s | 3 |

*Note: Only 95 routers declare a bandwidth tier. The majority do not set router capabilities.*

### Floodfill distribution

| Country | Floodfills |
|---|---|
| US | 20 |
| RU | 17 |
| DE | 10 |
| FI | 5 |
| NL | 3 |
| CA | 3 |
| AT | 3 |
| UA | 2 |
| PL | 2 |
| LT | 2 |
| IN | 2 |
| GB | 2 |
| VG | 1 |
| TR | 1 |
| SK | 1 |
| PT | 1 |
| MC | 1 |
| LU | 1 |
| IT | 1 |
| FR | 1 |
| ES | 1 |
| CZ | 1 |
| CH | 1 |
| BG | 1 |

### Congestion status

| Status | Routers |
|---|---|
| low | 19020 |
| medium | 8 |
| high | 3 |
| reject | 2 |

## 5. Version Ecosystem

| Version | Routers | Share |
|---|---|---|
| 0.9.68 | 9,427 | 49.5% |
| 0.9.69 | 3,627 | 19.1% |
| 0.9.67 | 1,752 | 9.2% |
| 0.9.61 | 1,386 | 7.3% |
| 0.9.65 | 714 | 3.8% |
| 0.9.64 | 666 | 3.5% |
| 0.9.57 | 431 | 2.3% |
| 0.9.66 | 372 | 2.0% |
| 0.9.60 | 121 | 0.6% |
| 0.9.62 | 110 | 0.6% |
| 0.9.59 | 99 | 0.5% |
| 0.9.63 | 98 | 0.5% |
| 0.9.56 | 88 | 0.5% |
| 0.9.58 | 71 | 0.4% |
| 0.9.54 | 33 | 0.2% |

## 6. Implementation Distribution

*(Classified by signing key type + router options + version heuristics)*

| Implementation | Routers | Share |
|---|---|---|
| i2pd | 19,033 | 100.0% |

### Implementation × Version (top 15)

| Implementation | Version | Count |
|---|---|---|
| i2pd | 0.9.68 | 9427 |
| i2pd | 0.9.69 | 3627 |
| i2pd | 0.9.67 | 1752 |
| i2pd | 0.9.61 | 1386 |
| i2pd | 0.9.65 | 714 |
| i2pd | 0.9.64 | 666 |
| i2pd | 0.9.57 | 431 |
| i2pd | 0.9.66 | 372 |
| i2pd | 0.9.60 | 121 |
| i2pd | 0.9.62 | 110 |
| i2pd | 0.9.59 | 99 |
| i2pd | 0.9.63 | 98 |
| i2pd | 0.9.56 | 88 |
| i2pd | 0.9.58 | 71 |
| i2pd | 0.9.54 | 33 |

## 7. IP Protocol

| Type | Routers | Share |
|---|---|---|
| IPv4 | 4,282 | 81.1% |
| IPv6 | 997 | 18.9% |

## 8. Methodology

- **Collection**: Multiple i2pd floodfill instances passively receive RouterInfo via the I2P DHT (Kademlia-like).
- **Dedup**: By `ident_hash` (SHA-256 of the full identity block including extended certificate).
- **Implementation detection**: Deep-parses the identity certificate structure — reads `signingKeyType` from the KEY certificate's extended buffer (bytes 387-390 of the RouterInfo). i2pd uses type 7 (EdDSA_SHA512_Ed25519) or type 11 (RedDSA), while Java I2P defaults to type 0 (DSA_SHA1) or type 4 (I2P-standard EdDSA). Additional heuristics from `router.version` and implementation-specific RouterInfo options (`i2pd.router=true`, `statServer`).
- **Known limitation — Java I2P invisible to i2pd**: All 19,033 detected routers use signing key type 7 (i2pd's EdDSA). No routers with type 4 (I2P-standard EdDSA, used by Java I2P 2.11.0+) were found. Source code analysis reveals i2pd 2.60.0's `CreateVerifier()` switch statement does not handle signing key type 4, causing RouterInfo from Java I2P routers to be rejected with "Identity: Signing key type not supported". This means Java I2P routers may exist on the network but are invisible to i2pd-based floodfill scanners. To detect them, a Java I2P/I2P+ floodfill or a patched i2pd is required.
- **Coverage**: Estimated ~90% of known routers after 24h with 5 floodfill instances (DHT-shard cross-coverage).
- **Hidden nodes**: Routers without a `host=` field do not expose an IP and are excluded from GeoIP statistics.
- **GeoIP**: MaxMind GeoLite2-Country database.
- **Limitations**: Passive collection only — 100% coverage is theoretically impossible due to the DHT sharding design.
