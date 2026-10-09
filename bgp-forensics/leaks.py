#!/usr/bin/env python3
"""Route-leak detection via the Gao-Rexford valley-free model.

A BGP AS path (observer -> origin) is valley-free iff it looks like:
    uphill (customer->provider)* , at most one peer-to-peer, downhill (provider->customer)*
A path that goes downhill and then back uphill (or uses a peer link in the
middle of a climb) violates the model -- the classic signature of a route
leak (e.g. a multi-homed AS re-announcing provider routes to another
provider). Relationships come from CAIDA's AS-relationship dataset.
"""
import bz2
import sys


def load_asrel(path):
    """Load CAIDA serial-2 as-rel file.

    Returns dict {(a,b): rel} with rel in {'p2c','c2p','p2p'} meaning the
    relationship of a TO b: 'p2c' = a is provider of b, etc.
    """
    rel = {}
    opener = bz2.open if path.endswith('.bz2') else open
    with opener(path, 'rt') as f:
        for line in f:
            if line.startswith('#') or not line.strip():
                continue
            parts = line.split('|')
            if len(parts) < 3:
                continue
            a, b, r = int(parts[0]), int(parts[1]), parts[2].strip()
            if r == '-1':      # a provider of b
                rel[(a, b)] = 'p2c'
                rel[(b, a)] = 'c2p'
            elif r == '1':     # a customer of b
                rel[(a, b)] = 'c2p'
                rel[(b, a)] = 'p2c'
            elif r == '0':     # peers
                rel[(a, b)] = 'p2p'
                rel[(b, a)] = 'p2p'
    return rel


def _dedup(path):
    out = []
    for asn in path:
        if not out or out[-1] != asn:
            out.append(asn)
    return out


def valley_free(path, rel):
    """Check one AS path (wire order: observer-side first, origin last).

    Returns (verdict, detail) where verdict is 'OK', 'LEAK', 'LOOP', or
    'INCONCLUSIVE' (unknown relationship on the path, no provable violation).
    """
    p = _dedup([a for a in path if a != 0])
    if len(p) < 2:
        return 'OK', 'single-AS path'
    if len(set(p)) != len(p):
        return 'LOOP', f'AS appears twice (non-prepend): {p}'
    phase = 0  # 0=uphill, 1=after-p2p, 2=downhill
    unknowns = []
    for i in range(len(p) - 1):
        x, y = p[i], p[i + 1]
        r = rel.get((x, y))
        if r is None:
            unknowns.append((x, y))
            continue
        step = {'c2p': 'up', 'p2c': 'down', 'p2p': 'peer'}[r]
        if phase == 0:
            if step == 'up':
                pass
            elif step == 'peer':
                phase = 1
            else:  # down
                phase = 2
        elif phase == 1:
            if step == 'down':
                phase = 2
            else:
                return 'LEAK', f'link {x}-{y} goes {step} after a peering link'
        else:  # phase 2
            if step != 'down':
                return 'LEAK', f'link {x}-{y} goes {step} after downhill started'
    if unknowns:
        return 'INCONCLUSIVE', f'{len(unknowns)} unknown link(s), e.g. {unknowns[0]}'
    return 'OK', 'valley-free'


def check_paths(paths, rel, limit=200):
    """paths: iterable of (label, as_path). Returns list of (label, verdict, detail, path)."""
    out = []
    for label, path in paths:
        verdict, detail = valley_free(path, rel)
        out.append((label, verdict, detail, path))
        if len(out) >= limit:
            break
    return out


if __name__ == '__main__':
    # smoke tests: wire order = observer side first, origin last
    rel = {(1, 2): 'c2p', (2, 1): 'p2c',     # 1 customer of 2
           (2, 3): 'p2p', (3, 2): 'p2p',     # 2 peers 3
           (3, 4): 'p2c', (4, 3): 'c2p',     # 3 provider of 4
           (1, 5): 'p2c', (5, 1): 'c2p',     # 1 provider of 5
           (5, 6): 'c2p', (6, 5): 'p2c',     # 5 customer of 6
           (2, 6): 'c2p', (6, 2): 'p2c'}     # 2 customer of 6
    tests = [
        # (path, expected)
        ([1, 2, 3, 4], 'OK'),            # up, peer, down
        ([1, 2, 3], 'OK'),               # up, peer
        ([3, 4], 'OK'),                  # down only
        ([5, 1, 2, 3], 'OK'),            # up, up, peer (5 is customer of 1)
        ([4, 3, 2, 1], 'OK'),            # up, peer, down
        ([1, 5, 6], 'LEAK'),             # down (1->5) then up (5->6): valley
        ([4, 3, 2, 6], 'LEAK'),          # up, peer, then up again after p2p
        ([1, 2, 3, 2, 4], 'LOOP'),       # non-prepend loop
        ([1, 1, 2, 3, 4], 'OK'),         # prepending dedups cleanly
        ([9, 1, 2], 'INCONCLUSIVE'),     # unknown link, no provable violation
        ([4], 'OK'),                     # single AS
    ]
    fails = 0
    for path, want in tests:
        got, detail = valley_free(path, rel)
        ok = got == want
        fails += not ok
        print(f'{"ok  " if ok else "FAIL"} {path} -> {got} ({detail})')
    sys.exit(1 if fails else 0)
