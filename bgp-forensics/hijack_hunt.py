#!/usr/bin/env python3
"""Hijack-shaped shortlist: DEAGG findings ranked by suspiciousness, with
full-path verification via targeted re-scan.

For each candidate: does the covering origin appear in the more-specific's
AS path (=> upstream delegation, likely benign), or is the path unrelated
(=> hijack-shaped)? Plus valley-free leak check on the fetched paths.
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from leaks import load_asrel, valley_free
import deepdive

BASE = _HERE if '_HERE' in dir() else os.path.dirname(os.path.abspath(__file__))


def rank_candidates(limit=400):
    rel = load_asrel(BASE + '/as-rel2.txt.bz2')
    cands = []
    with open(BASE + '/buckets/findings.jsonl') as f:
        for line in f:
            d = json.loads(line)
            if d['kind'] != 'DEAGG_ORIGIN_CHANGE':
                continue
            pfx = d['prefix']
            v6 = ':' in pfx
            addr, plen = pfx.split('/')
            plen = int(plen)
            cov_plen = int(d['covering'].split('/')[1])
            # hijack-shaped: exact /24 (v4) or /48 (v6) inside a real aggregate
            if (not v6 and plen != 24) or (v6 and plen != 48):
                continue
            if cov_plen > 21:
                continue
            if len(d['covering_origins']) != 1:
                continue
            cov_o = d['covering_origins'][0]
            orgs = d['origins']
            # skip clear provider->customer delegation
            skip = False
            for o in orgs:
                if rel.get((cov_o, o)) == 'p2c':
                    skip = True
            if skip:
                continue
            cands.append(d)
            if len(cands) >= limit:
                break
    return cands, rel


def main():
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    cands, rel = rank_candidates(limit)
    print(f'candidates: {len(cands)}')
    want4 = {d['prefix'] for d in cands if ':' not in d['prefix']}
    want6 = {d['prefix'] for d in cands if ':' in d['prefix']}
    print('targeted re-scan...', flush=True)
    got = deepdive.paths_for_prefixes(BASE + '/bview.20261008.0000.gz',
                                      want4, want6, limit_per_prefix=6)
    print(f'got paths for {len(got)}/{len(want4) + len(want6)} prefixes')
    n_upstream = n_unrelated = n_nopath = 0
    verdicts = {}
    showcased = []
    for d in cands:
        pfx = d['prefix']
        cov_o = d['covering_origins'][0]
        rows = got.get(pfx, [])
        if not rows:
            n_nopath += 1
            continue
        for peer_as, path, comms, nh in rows:
            if not path:
                continue
            upstream = cov_o in path
            if upstream:
                n_upstream += 1
            else:
                n_unrelated += 1
                if len(showcased) < 15:
                    showcased.append((pfx, d['covering'], d['origins'], cov_o,
                                      peer_as, path))
            v, detail = valley_free(path, rel)
            verdicts[v] = verdicts.get(v, 0) + 1
            break  # one path per prefix for the verdict counts
    print(f'\ncovering-origin-in-path (likely benign delegation): {n_upstream}')
    print(f'covering-origin-NOT-in-path (hijack-shaped):        {n_unrelated}')
    print(f'no rows returned: {n_nopath}')
    print('valley-free verdicts on sampled paths:', verdicts)
    print('\n--- hijack-shaped examples (covering origin absent from path) ---')
    for pfx, cov, orgs, cov_o, peer_as, path in showcased:
        print(f'{pfx:24s} origins={orgs} covering {cov} (AS{cov_o})')
        print(f'    via peer AS{peer_as}: path={path}')


if __name__ == '__main__':
    main()
