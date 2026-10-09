#!/usr/bin/env python3
"""bgpwatch -- BGP forensics CLI.

Subcommands:
  stats                 global RIB stats from buckets/stats.json
  findings [KIND]       list findings (MOAS, BOGON_ORIGIN, DEAGG_ORIGIN_CHANGE,
                        LONG_PATH, AS_SET, AS_TRANS_LEAK), optional kind filter
  lookup PREFIX         show findings + aggregate line for a prefix
  updates               5-minute updates-file report (churn, origin changes)
  leakcheck [--limit N] valley-free leak check on DEAGG/LONG_PATH/MOAS findings
                        (pulls full AS paths via targeted re-scan)
"""
import json
import os
import sys

BASE = _HERE if '_HERE' in dir() else os.path.dirname(os.path.abspath(__file__))
BUCKETS = os.path.join(BASE, 'buckets')
sys.path.insert(0, BASE)


def load_findings(kind=None, limit=100):
    out = []
    with open(os.path.join(BUCKETS, 'findings.jsonl')) as f:
        for line in f:
            d = json.loads(line)
            if kind and d['kind'] != kind:
                continue
            out.append(d)
            if len(out) >= limit:
                break
    return out


def cmd_stats():
    s = json.load(open(os.path.join(BUCKETS, 'stats.json')))
    print('=== RIB snapshot: RIPE RIS rrc00, 2026-10-08 00:00 UTC ===')
    for k in ('prefixes', 'entries', 'moas', 'bogon', 'deagg', 'long_path',
              'as_set', 'as_trans'):
        print(f'  {k:10s} {s.get(k, 0):>12,}')


def cmd_findings(kind=None, limit=50):
    rows = load_findings(kind, limit)
    print(f'=== findings{f" [{kind}]" if kind else ""} (first {len(rows)}) ===')
    for d in rows:
        k = d['kind']
        if k == 'MOAS':
            print(f"MOAS  {d['prefix']:22s} origins={d['origins']} peers={d['n_peers']}")
        elif k == 'BOGON_ORIGIN':
            print(f"BOGON {d['prefix']:22s} origin=AS{d['origin']} ({d['label']})")
        elif k == 'DEAGG_ORIGIN_CHANGE':
            print(f"DEAGG {d['prefix']:22s} origins={d['origins']} "
                  f"covering {d['covering']} origins={d['covering_origins']}")
        elif k == 'LONG_PATH':
            print(f"LONGP {d['prefix']:22s} maxlen={d['maxlen']} origins={d['origins']}")
        elif k == 'AS_SET':
            print(f"ASSET {d['prefix']:22s} origins={d['origins']}")
        elif k == 'AS_TRANS_LEAK':
            print(f"ASTRN {d['prefix']:22s} origins={d['origins']}")


def cmd_lookup(prefix):
    print(f'=== lookup {prefix} ===')
    found = False
    with open(os.path.join(BUCKETS, 'findings.jsonl')) as f:
        for line in f:
            d = json.loads(line)
            if d['prefix'] == prefix:
                print(json.dumps(d, indent=1))
                found = True
    # aggregate line
    import glob
    import ipaddress
    addr, plen = prefix.split('/')
    v6 = ':' in addr
    first = int(addr.split('.')[0]) if not v6 else int(addr.split(':')[0] or '0', 16)
    for apath in glob.glob(os.path.join(BUCKETS, f"bv{'6' if v6 else '4'}_{first:03d}.agg")):
        with open(apath) as f:
            for line in f:
                p = line.split('|')
                if int(p[1]) != int(plen):
                    continue
                a = (ipaddress.IPv6Address(bytes.fromhex(p[2])) if v6
                     else ipaddress.IPv4Address(int(p[2], 16)))
                if str(a) == addr:
                    print('aggregate:', line.strip())
                    found = True
    if not found:
        print('no findings or aggregate for this prefix')


def cmd_updates():
    import updates_watch
    stats, events = updates_watch.analyze(os.path.join(BASE, 'updates.20261008.0000.gz'))
    print('=== 5-minute updates window (2026-10-08 00:00-00:05 UTC) ===')
    for k in ('updates', 'announced_nlri', 'withdrawn_nlri', 'unique_prefixes',
              'flaps', 'origin_changes', 'blackhole', 'v6_nlri'):
        print(f'  {k:16s} {stats[k]:>10,}')
    print('\n  top churn:')
    for c in stats['top_churn'][:10]:
        print(f"    {c['prefix']:22s} ann={c['ann']:>6,} wd={c['wd']:>4,} origin=AS{c['origin']}")
    print(f'\n  origin changes: {len(events)} (first 10)')
    for e in events[:10]:
        print(f"    {e['prefix']:24s} AS{e['old_origin']} -> AS{e['new_origin']} "
              f"via peer AS{e['peer_as']}")


def cmd_leakcheck(limit=60):
    import deepdive
    import leaks
    print('loading CAIDA as-rel...', flush=True)
    rel = leaks.load_asrel(os.path.join(BASE, 'as-rel2.txt.bz2'))
    print(f'  {len(rel) // 2} relationships')
    want4, want6 = set(), set()
    for d in load_findings(limit=100000):
        if d['kind'] in ('DEAGG_ORIGIN_CHANGE', 'LONG_PATH'):
            (want6 if ':' in d['prefix'] else want4).add(d['prefix'])
        if len(want4) + len(want6) >= limit:
            break
    print(f'targeted re-scan for {len(want4) + len(want6)} prefixes...', flush=True)
    got = deepdive.paths_for_prefixes(
        os.path.join(BASE, 'bview.20261008.0000.gz'), want4, want6,
        limit_per_prefix=4)
    paths = []
    for pfx, rows in got.items():
        for peer_as, path, comms, nh in rows:
            if len(path) >= 2:
                paths.append((f'{pfx} via AS{peer_as}', path))
    print(f'checking {len(paths)} paths...', flush=True)
    res = leaks.check_paths(paths, rel, limit=100000)
    counts = {}
    for label, verdict, detail, path in res:
        counts[verdict] = counts.get(verdict, 0) + 1
        if verdict in ('LEAK', 'LOOP'):
            print(f'{verdict:5s} {label}: {detail}\n       path={path}')
    print('verdicts:', counts)


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__)
        return
    cmd = sys.argv[1]
    if cmd == 'stats':
        cmd_stats()
    elif cmd == 'findings':
        kind = sys.argv[2].upper() if len(sys.argv) > 2 else None
        limit = int(sys.argv[3]) if len(sys.argv) > 3 else 50
        cmd_findings(kind, limit)
    elif cmd == 'lookup':
        cmd_lookup(sys.argv[2])
    elif cmd == 'updates':
        cmd_updates()
    elif cmd == 'leakcheck':
        limit = int(sys.argv[2]) if len(sys.argv) > 2 else 60
        cmd_leakcheck(limit)
    else:
        print(f'unknown command: {cmd}')
        print(__doc__)


if __name__ == '__main__':
    main()
