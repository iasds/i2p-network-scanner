#!/usr/bin/env python3
"""v4 - Quick scanner for i2pd 2.60.0 netdb routerInfo-*.dat files.
Properly parses identity certificate to extract signing key type,
correctly compute ident_hash, and classify Java I2P vs i2pd."""

import sys, os, json, hashlib, re, struct
from pathlib import Path
from typing import Optional

I2P_B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-~"

# i2pd signing key type enum (from Identity.h)
SIGNING_KEY_TYPE_DSA_SHA1 = 0
SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 = 7
SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519 = 11
SIGNING_KEY_TYPE_GOST_256 = 9
SIGNING_KEY_TYPE_GOST_512 = 10

# Certificate types
CERT_TYPE_NULL = 0
CERT_TYPE_KEY = 5

DEFAULT_IDENTITY_SIZE = 387  # sizeof(Identity) = publicKey[256] + signingKey[128] + certificate[3]


def i2p_b64encode(data: bytes) -> str:
    buf = []
    val = bits = 0
    for b in data:
        val = (val << 8) | b
        bits += 8
        while bits >= 6:
            bits -= 6
            buf.append(I2P_B64[(val >> bits) & 0x3F])
    if bits > 0:
        buf.append(I2P_B64[(val << (6 - bits)) & 0x3F])
    while len(buf) % 4 != 0:
        buf.append('=')
    return ''.join(buf)


def parse_identity(raw: bytes) -> Optional[dict]:
    """Parse I2P IdentityEx from raw on-disk RouterInfo bytes.
    
    Standard Identity layout (387 bytes):
      [0:256]   encryptionPublicKey  - X25519 pub (first 32B) + padding
      [256:384] signingKey           - EdDSA pub (first 32B) + padding  
      [384]     certificate_type     - 0=NULL, 5=KEY
      [385:387] certificate_len      - total cert length, big-endian 16-bit
    
    Extended buffer (if KEY cert): follows at offset 387
      [0:2] signing_key_type (big-endian 16-bit)
      [2:4] crypto_key_type  (big-endian 16-bit)
    """
    if len(raw) < DEFAULT_IDENTITY_SIZE:
        return None
    
    cert_type = raw[384]
    cert_len = struct.unpack('>H', raw[385:387])[0]  # big-endian 16-bit
    
    # Determine full identity length
    # In i2pd's on-disk format, the cert_len field (bytes 385-386, big-endian)
    # IS the extended data length directly (not total cert length).
    # The extended buffer follows at offset DEFAULT_IDENTITY_SIZE.
    if cert_type == CERT_TYPE_KEY and cert_len >= 2:
        extended_len = cert_len          # i2pd stores extended_len directly
        full_ident_len = DEFAULT_IDENTITY_SIZE + extended_len
    else:
        extended_len = 0
        full_ident_len = DEFAULT_IDENTITY_SIZE
    
    if full_ident_len > len(raw):
        return None
    
    ident = raw[:full_ident_len]
    h = hashlib.sha256(ident).digest()
    ident_hash = i2p_b64encode(h)
    
    # Parse signing key type from extended buffer
    if cert_type == CERT_TYPE_KEY and extended_len >= 2:
        signing_key_type = struct.unpack('>H', raw[387:389])[0]
    else:
        signing_key_type = SIGNING_KEY_TYPE_DSA_SHA1  # default for NULL cert
    
    return {
        'crypto_type': signing_key_type,
        'ident_hash': ident_hash,
        'ident_len': full_ident_len,
        'cert_type': cert_type,
        'cert_len': cert_len,
        'extended_len': extended_len,
    }


def classify_implementation(signing_key_type: int, options: dict, version: str) -> str:
    """Classify as 'java-i2p', 'i2pd', or 'unknown'.
    
    Key insight: i2pd uses its own signing key type enum (Identity.h)
    which differs from the I2P standard:
      I2P std: EdDSA_Ed25519 = 4
      i2pd:    EdDSA_SHA512_Ed25519 = 7  (because RSA types 4-6 inserted)
               RedDSA_Ed25519 = 11       (matches I2P standard)
    """
    # Strong signals from router options
    if options.get('i2pd.router') == 'true':
        return 'i2pd'
    if 'statServer' in options:
        return 'java-i2p'
    if 'router.interface' in options:
        return 'java-i2p'
    if 'I2P.router' in options:
        return 'java-i2p'
    
    # Signing key type heuristics
    # i2pd exclusive types
    if signing_key_type == SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519:  # 7
        return 'i2pd'
    if signing_key_type == SIGNING_KEY_TYPE_REDDSA_SHA512_ED25519:  # 11
        return 'i2pd'
    if signing_key_type == SIGNING_KEY_TYPE_GOST_256 or \
       signing_key_type == SIGNING_KEY_TYPE_GOST_512:
        return 'i2pd'
    
    # Standard I2P EdDSA (type 4) → Java I2P (i2pd doesn't use this value)
    if signing_key_type == 4:
        return 'java-i2p'
    
    # Type 0 (DSA_SHA1): default for both, check version
    if signing_key_type == SIGNING_KEY_TYPE_DSA_SHA1:
        if version:
            if version.startswith('2.'):
                return 'i2pd'
            if version.startswith('0.9.'):
                return 'java-i2p'
        return 'java-i2p'  # DSA is the traditional Java I2P default
    
    # Version heuristic for other cases
    if version:
        if version.startswith('2.'):
            return 'i2pd'
        if version.startswith('0.9.'):
            return 'java-i2p'
    
    return 'unknown'


def parse_router_info_v4(raw: bytes) -> Optional[dict]:
    """Parse RouterInfo from on-disk bytes. Returns dict or None."""
    if len(raw) < 70:
        return None
    
    # Parse identity
    ident_info = parse_identity(raw)
    if ident_info is None:
        return None
    
    ident_len = ident_info['ident_len']
    payload = raw[ident_len:]
    
    ri = {
        'ident_hash': ident_info['ident_hash'],
        'crypto_type': ident_info['crypto_type'],
        'ident_len': ident_len,
        'cert_type': ident_info['cert_type'],
        'addresses': [],
    }
    
    # --- Extract addresses ---
    for transport in [b'NTCP2', b'SSU2']:
        pos = 0
        while True:
            idx = payload.find(transport, pos)
            if idx < 0:
                break
            transport_end = idx + len(transport)
            if transport_end >= len(payload) or payload[transport_end] != 0:
                pos = transport_end
                continue
            
            chunk_start = transport_end + 1
            chunk_end = min(chunk_start + 200, len(payload))
            chunk = payload[chunk_start:chunk_end]
            
            addr = {'transport': transport.decode()}
            
            # host=
            hm = re.search(rb'host=([^;\x00]+)', chunk)
            if hm:
                val = hm.group(1)
                if val and (val[0] < 32 or val[0] > 126):
                    val = val[1:]
                addr['ip'] = val.decode('ascii', errors='replace')
                addr['v6'] = ':' in addr['ip']
                addr['v4'] = ':' not in addr['ip']
            
            # port=
            pm = re.search(rb'port=.[0-9]{1,5}', chunk)
            if pm:
                val = pm.group(0)
                eq_pos = val.find(b'=')
                if eq_pos >= 0:
                    digits = bytes(b for b in val[eq_pos+2:] if 48 <= b <= 57)
                    if digits:
                        addr['port'] = int(digits)
            
            if addr.get('ip') and addr.get('port', 0) > 0:
                ri['addresses'].append(addr)
            
            pos = transport_end + 200
    
    # --- Router options ---
    text = payload.decode('latin-1', errors='replace')
    
    # Collect all options for classification
    options = {}
    for m in re.finditer(rb'([a-zA-Z0-9_.]+)=([^;\x00]+)', payload):
        key = m.group(1).decode('ascii', errors='replace')
        val_bytes = bytes(b for b in m.group(2) if 32 <= b < 127)
        val = val_bytes.decode('ascii', errors='replace')
        options[key] = val
    
    ri['options'] = options
    
    # caps
    cm = re.search(rb'caps=[\x00-\x1f]?([^\x00;]+)', payload)
    if cm:
        caps_raw = cm.group(1)
        caps_str = ''
        for b in caps_raw:
            if 32 <= b < 127:
                caps_str += chr(b)
        for c in caps_str:
            if c == 'f': ri['is_floodfill'] = True
            elif c == 'H': ri['is_hidden'] = True
            elif c == 'R': ri['is_reachable'] = True
            elif c == 'U': ri['is_unreachable'] = True
            elif c in 'KLMNOPX': ri['bandwidth_tier'] = c
            elif c == 'D': ri['congestion'] = 'medium'
            elif c == 'E': ri['congestion'] = 'high'
            elif c == 'G': ri['congestion'] = 'reject'
    
    # version
    vm = re.search(rb'router\.version=[\x00-\x1f]?([^\x00;]+)', payload)
    if vm:
        val = vm.group(1)
        clean = bytes(b for b in val if 32 <= b < 127)
        ri['version'] = clean.decode('ascii', errors='replace')
    
    # family
    fm = re.search(rb'family=([^\x00;]+)', payload)
    if fm:
        val = fm.group(1).decode('ascii', errors='replace').strip('\x00-\x1f')
        ri['family'] = ''.join(c for c in val if 32 <= ord(c) < 127)
    
    # knownRouters
    km = re.search(rb'netdb\.knownRouters=(\d+)', payload)
    if km:
        ri['known_routers'] = int(km.group(1))
    
    # --- Classify implementation ---
    ri['implementation'] = classify_implementation(
        ident_info['crypto_type'], options, ri.get('version')
    )
    
    return ri


def scan_netdb(netdb_dir: str) -> list:
    results = []
    netdb = Path(netdb_dir)
    if not netdb.exists():
        print(f"[!] Directory not found: {netdb_dir}")
        return results
    
    files = list(netdb.glob("r*/routerInfo-*.dat"))
    total = len(files)
    parsed = 0
    errors = 0
    
    for i, f in enumerate(files):
        try:
            raw = f.read_bytes()
            ri = parse_router_info_v4(raw)
            if ri:
                results.append(ri)
                parsed += 1
            else:
                errors += 1
        except Exception as e:
            errors += 1
        
        if (i + 1) % 500 == 0:
            print(f"  ... {i+1}/{total} files scanned")
    
    print(f"  Files: {total}, Parsed: {parsed}, Errors: {errors}")
    return results


def main():
    netdb_dirs = [
        "/var/lib/i2pd/netDb",
        "/var/lib/i2pd/netdb",
        "/var/lib/i2pd/instances/1/netDb",
        "/var/lib/i2pd/instances/2/netDb",
        "/var/lib/i2pd/instances/3/netDb",
        "/var/lib/i2pd/instances/4/netDb",
        "/var/lib/i2pd/instances/5/netDb",
    ]
    
    all_routers = []
    for d in netdb_dirs:
        if os.path.isdir(d):
            print(f"Scanning: {d}")
            routers = scan_netdb(d)
            all_routers.extend(routers)
    
    if not all_routers:
        print("\n[!] No routers found.")
        return
    
    # Dedup by ident_hash
    seen = {}
    for r in all_routers:
        h = r['ident_hash']
        if h not in seen:
            seen[h] = r
    unique = list(seen.values())
    
    print(f"\n{'='*60}")
    print(f"Total routers: {len(all_routers)} (unique: {len(unique)})")
    print(f"{'='*60}")
    
    ff = sum(1 for r in unique if r.get('is_floodfill'))
    hid = sum(1 for r in unique if r.get('is_hidden'))
    reach = sum(1 for r in unique if r.get('is_reachable'))
    print(f"Floodfills:   {ff}")
    print(f"Hidden:       {hid}")
    print(f"Reachable:    {reach}")
    has_addr = sum(1 for r in unique if r.get('addresses'))
    
    # Implementation dist
    impl = {}
    for r in unique:
        i = r.get('implementation', 'unknown')
        impl[i] = impl.get(i, 0) + 1
    print(f"\nImplementation distribution:")
    for i, c in sorted(impl.items(), key=lambda x: -x[1]):
        print(f"  {i:12s} {c:5d}")
    
    # Crypto type dist
    ct = {}
    for r in unique:
        t = r.get('crypto_type', -1)
        ct[t] = ct.get(t, 0) + 1
    print(f"\nSigning key type distribution:")
    for t, c in sorted(ct.items(), key=lambda x: -x[1]):
        label = {
            0: 'DSA_SHA1',
            7: 'EdDSA_Ed25519',
            11: 'RedDSA_Ed25519',
        }.get(t, f'type_{t}')
        print(f"  {label:20s} {c:5d}")
    
    # Version dist
    versions = {}
    for r in unique:
        v = r.get('version', 'unknown')
        versions[v] = versions.get(v, 0) + 1
    print(f"\nVersion distribution (top 10):")
    for v, c in sorted(versions.items(), key=lambda x: -x[1])[:10]:
        print(f"  {v:20s} {c:5d}")
    
    # Bandwidth dist
    bw = {}
    for r in unique:
        b = r.get('bandwidth_tier', '?')
        bw[b] = bw.get(b, 0) + 1
    print(f"\nBandwidth tiers:")
    for t in 'KLMNOPX?':
        if t in bw:
            print(f"  {t}: {bw[t]}")
    
    # Transport dist
    transports = {}
    for r in unique:
        for a in r.get('addresses', []):
            t = a.get('transport', '?')
            transports[t] = transports.get(t, 0) + 1
    print(f"\nTransports:")
    for t, n in sorted(transports.items()):
        print(f"  {t}: {n}")
    
    # IP summary
    all_ips = set()
    for r in unique:
        for a in r.get('addresses', []):
            if a.get('ip'):
                all_ips.add(a['ip'])
    print(f"\nUnique IPs:     {len(all_ips)}")
    print(f"Routers w/ IP:  {has_addr}/{len(unique)}")
    print(f"IPv4 only:      {sum(1 for r in unique if any(a.get('v4') for a in r.get('addresses', [])))}")
    print(f"IPv6 support:   {sum(1 for r in unique if any(a.get('v6') for a in r.get('addresses', [])))}")
    
    # JSON export
    out_path = "/tmp/i2p_netdb_scan.json"
    with open(out_path, 'w') as f:
        json.dump(unique, f, indent=2, default=str)
    print(f"\nFull JSON export: {out_path} ({os.path.getsize(out_path)/1024:.0f} KB)")


if __name__ == '__main__':
    main()
