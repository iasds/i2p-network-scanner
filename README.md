# I2P NetDB Collector

Passively collect and analyze the I2P network's entire router database (NetDB) using multiple i2pd floodfill instances — no active crawling required.

## How it works

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│  i2pd #1 │  │  i2pd #2 │  │  i2pd #N │   floodfill instances
│  :10201  │  │  :10202  │  │  :1020N  │   (different DHT shards)
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │  netDb/      │  netDb/      │  netDb/
     │  *.dat       │  *.dat       │  *.dat
     └──────┬───────┴──────┬───────┘
            │              │
     ┌──────▼──────────────▼──────┐
     │     quick_scan.py          │   parse every routerInfo-*.dat
     │  • ident_hash, version     │
     │  • IP, port, transport     │
     │  • caps flags, bandwidth   │
     │  • GeoIP (MaxMind mmdb)    │
     └────────────┬───────────────┘
                  │
     ┌────────────▼───────────────┐
     │     import_db.py           │   JSON → SQLite
     │     analyze.py             │   reports + GeoIP enrichment
     │     query_db.py            │   CLI queries
     └────────────────────────────┘
```

Each i2pd floodfill receives a **different DHT shard** based on its identity hash. Running 3–5 instances with distinct identities provides ~90% coverage of known routers after ~24 hours.

## Requirements

- **VPS with a public IP** (floodfills must be reachable)
- i2pd ≥ 2.54.0 (`apt install i2pd` from [repo.i2pd.xyz](https://repo.i2pd.xyz))
- Python 3.9+
- [MaxMind GeoLite2-Country.mmdb](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (optional, for GeoIP)

## Quick start

### 1. Deploy floodfill instances on your VPS

Start N i2pd instances, each with a unique datadir and port:

```bash
for i in 1 2 3 4 5; do
  port=$((10200 + i))
  dir=/var/lib/i2pd/instances/$i
  mkdir -p $dir
  cat > $dir/i2pd.conf <<EOF
loglevel = info
floodfill = true
bandwidth = L
port = $port

[limits]
ntcpsoft = 100
transittunnels = 30
EOF
  nohup i2pd --conf=$dir/i2pd.conf --datadir=$dir > $dir/i2pd.log 2>&1 &
done
```

> **Note**: On Debian, i2pd's AppArmor profile restricts writes to `/var/lib/i2pd/`. Either place instances there or disable the profile (`aa-disable i2pd`).

### 2. Run the scanner

```bash
# One-off scan
python3 quick_scan.py

# Hourly cron
echo '#!/bin/bash
python3 /opt/i2p-collector/quick_scan.py > /opt/i2p-collector/scan.log 2>&1' \
  > /etc/cron.hourly/i2p-scan
chmod +x /etc/cron.hourly/i2p-scan
```

Output: `/tmp/i2p_netdb_scan.json`

### 3. Import and analyze locally

```bash
# Pull data from VPS
scp user@vps:/tmp/i2p_netdb_scan.json data/

# Import into SQLite
python3 import_db.py data/i2p_netdb_scan.json data/i2p_nodes.db

# Query
python3 query_db.py stats
python3 query_db.py search 185.151
python3 query_db.py ips 20

# Generate GeoIP-enriched report
python3 analyze.py --geodb /path/to/GeoLite2-Country.mmdb --enrich
```

## Schema

`routers` table in `i2p_nodes.db`:

| Column | Type | Description |
|---|---|---|
| `ident_hash` | TEXT PK | SHA-256 of identity block, base64 |
| `version` | TEXT | e.g. `0.9.69` |
| `is_floodfill` | INT | Floodfill capability flag |
| `is_reachable` | INT | Reachable flag |
| `is_hidden` | INT | Hidden flag |
| `bandwidth_tier` | TEXT | K / L / M / N / O / P / X |
| `congestion` | TEXT | low / medium / high / reject |
| `first_ip` | TEXT | Primary IP address |
| `transports` | TEXT | `NTCP2,SSU2`, `NTCP2`, or `SSU2` |
| `addresses_json` | TEXT | Full address list as JSON |
| `country` | TEXT | ISO 3166-1 alpha-2 (after GeoIP) |
| `continent` | TEXT | Continent code (after GeoIP) |

## Reports

See [`I2P_NETWORK_ANALYSIS.md`](I2P_NETWORK_ANALYSIS.md) for a sample analysis with country distribution, version breakdown, bandwidth tiers, and floodfill geography.

## Limitations

- **Coverage ceiling**: DHT sharding means 100% is theoretically impossible via passive collection alone. 5 instances ≈ 90% coverage.
- **Hidden nodes**: ~70% of I2P routers sit behind NAT and do not publish IPs. These are correctly recorded but excluded from GeoIP statistics.
- **No active probing**: This tool only reads what floodfills passively receive. It does not send `DatabaseLookup` messages.

## License

MIT
