#!/usr/bin/env python3
"""Import i2p_netdb_scan.json → SQLite database with dedup and query helpers."""

import json, sqlite3, sys, os
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS routers (
    ident_hash      TEXT PRIMARY KEY,
    crypto_type     INTEGER NOT NULL DEFAULT 4,
    implementation  TEXT,
    version         TEXT,
    is_floodfill    INTEGER NOT NULL DEFAULT 0,
    is_hidden       INTEGER NOT NULL DEFAULT 0,
    is_reachable    INTEGER NOT NULL DEFAULT 0,
    bandwidth_tier  TEXT,
    congestion      TEXT NOT NULL DEFAULT 'low',
    family          TEXT,
    known_routers   INTEGER,
    addresses_json  TEXT NOT NULL DEFAULT '[]',
    ip_count        INTEGER NOT NULL DEFAULT 0,
    first_ip        TEXT,
    ports           TEXT,
    transports      TEXT,
    first_seen      INTEGER,
    last_seen       INTEGER,
    seen_count      INTEGER NOT NULL DEFAULT 1
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS idx_routers_version ON routers(version);
CREATE INDEX IF NOT EXISTS idx_routers_floodfill ON routers(is_floodfill);
CREATE INDEX IF NOT EXISTS idx_routers_bw ON routers(bandwidth_tier);
CREATE INDEX IF NOT EXISTS idx_routers_first_ip ON routers(first_ip);
"""

def import_json(json_path: str, db_path: str):
    print(f"Loading {json_path}...")
    with open(json_path) as f:
        routers = json.load(f)
    print(f"  {len(routers)} routers in JSON")

    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")

    now = int(__import__('time').time())
    inserted, updated = 0, 0

    for ri in routers:
        h = ri['ident_hash']
        addrs = ri.get('addresses', [])
        ips = [a.get('ip', '') for a in addrs if a.get('ip')]
        ports = [str(a.get('port', '')) for a in addrs if a.get('port')]
        transports = list(set(a.get('transport', '') for a in addrs if a.get('transport')))

        db.execute("""
            INSERT INTO routers (
                ident_hash, crypto_type, implementation, version,
                is_floodfill, is_hidden, is_reachable,
                bandwidth_tier, congestion, family, known_routers,
                addresses_json, ip_count, first_ip, ports, transports,
                first_seen, last_seen, seen_count
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1)
            ON CONFLICT(ident_hash) DO UPDATE SET
                crypto_type = excluded.crypto_type,
                implementation = excluded.implementation,
                version = excluded.version,
                is_floodfill = excluded.is_floodfill,
                is_hidden = excluded.is_hidden,
                is_reachable = excluded.is_reachable,
                bandwidth_tier = excluded.bandwidth_tier,
                congestion = excluded.congestion,
                family = excluded.family,
                known_routers = excluded.known_routers,
                addresses_json = excluded.addresses_json,
                ip_count = excluded.ip_count,
                first_ip = excluded.first_ip,
                ports = excluded.ports,
                transports = excluded.transports,
                last_seen = excluded.last_seen,
                seen_count = routers.seen_count + 1
        """, (
            h,
            ri.get('crypto_type', 4),
            ri.get('implementation'),
            ri.get('version'),
            1 if ri.get('is_floodfill') else 0,
            1 if ri.get('is_hidden') else 0,
            1 if ri.get('is_reachable') else 0,
            ri.get('bandwidth_tier'),
            ri.get('congestion', 'low'),
            ri.get('family'),
            ri.get('known_routers'),
            json.dumps(addrs),
            len(ips),
            ips[0] if ips else None,
            ','.join(ports) if ports else None,
            ','.join(sorted(transports)) if transports else None,
            now,
            now,
        ))

        # Check if row was inserted or updated
        if db.total_changes > (inserted + updated):
            inserted += 1
        else:
            updated += 1

    db.commit()

    # Stats
    total = db.execute("SELECT COUNT(*) FROM routers").fetchone()[0]
    ff = db.execute("SELECT COUNT(*) FROM routers WHERE is_floodfill=1").fetchone()[0]
    with_ip = db.execute("SELECT COUNT(*) FROM routers WHERE ip_count > 0").fetchone()[0]
    unique_ips = db.execute("SELECT COUNT(DISTINCT first_ip) FROM routers WHERE first_ip IS NOT NULL").fetchone()[0]

    print(f"\n{'='*50}")
    print(f"Database: {db_path}")
    print(f"Total routers:  {total}")
    print(f"Floodfills:     {ff}")
    print(f"With IP:        {with_ip}")
    print(f"Unique IPs:     {unique_ips}")
    print(f"Inserted:       {inserted}")
    print(f"Updated:        {updated}")

    # Version dist
    print(f"\nTop versions:")
    for row in db.execute("SELECT version, COUNT(*) c FROM routers WHERE version IS NOT NULL GROUP BY version ORDER BY c DESC LIMIT 10"):
        print(f"  {row[0]:15s} {row[1]:5d}")

    # Transport dist
    print(f"\nTransports:")
    for row in db.execute("SELECT transports, COUNT(*) c FROM routers WHERE transports IS NOT NULL GROUP BY transports ORDER BY c DESC"):
        print(f"  {row[0]:20s} {row[1]:5d}")

    # Country stubs (placeholder until GeoIP)
    print(f"\nSample routers:")
    for row in db.execute("SELECT ident_hash, version, first_ip, transports FROM routers WHERE first_ip IS NOT NULL LIMIT 10"):
        print(f"  {row[0][:12]:12s} {row[1] or '?':8s} {row[2] or '?':20s} {row[3] or '?'}")

    db.close()
    print(f"\nDone. Size: {os.path.getsize(db_path)/1024:.0f} KB")


if __name__ == '__main__':
    json_path = sys.argv[1] if len(sys.argv) > 1 else 'data/i2p_netdb_scan.json'
    db_path = sys.argv[2] if len(sys.argv) > 2 else 'data/i2p_nodes.db'
    import_json(json_path, db_path)
