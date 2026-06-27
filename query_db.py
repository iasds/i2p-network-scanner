#!/usr/bin/env python3
"""Quick query tool for i2p_nodes.db"""

import sqlite3, sys

DB = 'data/i2p_nodes.db'

def query(sql, params=()):
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    rows = db.execute(sql, params).fetchall()
    db.close()
    return rows

def cmd_stats():
    total = query("SELECT COUNT(*) c FROM routers")[0][0]
    ff = query("SELECT COUNT(*) c FROM routers WHERE is_floodfill=1")[0][0]
    reachable = query("SELECT COUNT(*) c FROM routers WHERE is_reachable=1")[0][0]
    hidden = query("SELECT COUNT(*) c FROM routers WHERE is_hidden=1")[0][0]
    with_ip = query("SELECT COUNT(*) c FROM routers WHERE first_ip IS NOT NULL")[0][0]
    unique_ips = query("SELECT COUNT(DISTINCT first_ip) c FROM routers WHERE first_ip IS NOT NULL")[0][0]
    
    print(f"Total:     {total}")
    print(f"Floodfill: {ff}")
    print(f"Reachable: {reachable}")
    print(f"Hidden:    {hidden}")
    print(f"With IP:   {with_ip}")
    print(f"Unique IP: {unique_ips}")
    
    print(f"\nTop 10 versions:")
    for r in query("SELECT version, COUNT(*) c FROM routers WHERE version IS NOT NULL GROUP BY version ORDER BY c DESC LIMIT 10"):
        print(f"  {r['version']:12s} {r['c']:5d}")
    
    print(f"\nBandwidth tiers:")
    for r in query("SELECT bandwidth_tier, COUNT(*) c FROM routers WHERE bandwidth_tier IS NOT NULL GROUP BY bandwidth_tier ORDER BY c DESC"):
        print(f"  {r['bandwidth_tier']}: {r['c']}")

def cmd_ips(limit=50):
    for r in query("SELECT ident_hash, version, first_ip, transports FROM routers WHERE first_ip IS NOT NULL ORDER BY first_ip LIMIT ?", (limit,)):
        print(f"  {r['ident_hash'][:12]:12s} {r['version'] or '?':8s} {r['first_ip']:25s} {r['transports'] or '?'}")

def cmd_search(q, limit=20):
    for r in query("SELECT ident_hash, version, first_ip, transports FROM routers WHERE ident_hash LIKE ? OR first_ip LIKE ? OR version LIKE ? LIMIT ?", 
                   (f'%{q}%', f'%{q}%', f'%{q}%', limit)):
        print(f"  {r['ident_hash'][:12]:12s} {r['version'] or '?':8s} {r['first_ip'] or '?':25s} {r['transports'] or '?'}")

def cmd_export(filter_sql='1=1', out='-'):
    rows = query(f"SELECT * FROM routers WHERE {filter_sql}")
    import json
    data = [dict(r) for r in rows]
    if out == '-':
        print(json.dumps(data, indent=2))
    else:
        with open(out, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"Exported {len(data)} routers to {out}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: python3 query_db.py <command> [args]")
        print("  stats           — overview statistics")
        print("  ips [N]         — list routers with IPs")
        print("  search <term>   — search by hash/IP/version")
        print("  export [sql]    — export filtered JSON")
        print("  sql <statement> — raw SQL query")
        sys.exit(1)
    
    cmd = sys.argv[1]
    if cmd == 'stats':
        cmd_stats()
    elif cmd == 'ips':
        cmd_ips(int(sys.argv[2]) if len(sys.argv) > 2 else 50)
    elif cmd == 'search':
        cmd_search(sys.argv[2] if len(sys.argv) > 2 else '')
    elif cmd == 'export':
        cmd_export(sys.argv[2] if len(sys.argv) > 2 else '1=1', sys.argv[3] if len(sys.argv) > 3 else '-')
    elif cmd == 'sql':
        for r in query(sys.argv[2]):
            print(dict(r))
    else:
        print(f"Unknown command: {cmd}")
