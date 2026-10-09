#!/usr/bin/env python3
"""Analyze a BGP updates dump: churn, flaps, origin changes, blackhole signals.

Streams an MRT updates file (BGP4MP). For each announced prefix tracks the
last origin AS; an announcement with a *different* origin than previously
seen is an ORIGIN_CHANGE event -- the classic live-hijack signature.
Also counts withdrawals/flaps and 65535:666 (blackhole) community use.
"""
import gzip
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import mrt


def analyze(path, max_events=10000):
    state = {}   # prefix -> [origin, n_ann, n_wd, last_peer]
    events = []
    stats = {'updates': 0, 'announced_nlri': 0, 'withdrawn_nlri': 0,
             'unique_prefixes': 0, 'flaps': 0, 'origin_changes': 0,
             'blackhole': 0, 'v6_nlri': 0}
    with gzip.open(path, 'rb') as f:
        for ts, typ, sub, payload in mrt.iter_mrt_records(f):
            if typ != mrt.BGP4MP or sub not in (mrt.BGP4MP_MESSAGE, mrt.BGP4MP_MESSAGE_AS4):
                continue
            try:
                info = mrt.parse_bgp_message(payload, asn4=(sub == mrt.BGP4MP_MESSAGE_AS4))
            except mrt.MRTError:
                continue
            if info['bgp_type'] != mrt.BGP_UPDATE:
                continue
            stats['updates'] += 1
            u = info['update']
            try:
                attrs = mrt.parse_path_attributes(u['attr_raw'], asn4=(sub == mrt.BGP4MP_MESSAGE_AS4))
            except mrt.MRTError:
                continue
            origin = mrt.origin_as(attrs)
            path = mrt.as_path_flat(attrs)
            comms = attrs.get('communities', [])
            if '65535:666' in comms:
                stats['blackhole'] += len(u['announced'])
            mp = attrs.get('mp_reach')
            announced = list(u['announced'])
            if mp:
                stats['v6_nlri'] += len(mp['nlri'])
                announced += [(a, p) for a, p in mp['nlri']]
            for addr, plen in u['withdrawn']:
                stats['withdrawn_nlri'] += 1
                key = f'{addr}/{plen}'
                st = state.get(key)
                if st is not None:
                    st[2] += 1
            for addr, plen in announced:
                stats['announced_nlri'] += 1
                key = f'{addr}/{plen}'
                st = state.get(key)
                if st is None:
                    state[key] = [origin, 1, 0, info['peer_as']]
                    stats['unique_prefixes'] += 1
                else:
                    st[1] += 1
                    if st[2] > 0:
                        stats['flaps'] += 1  # withdrawn then re-announced
                        st[2] = 0
                    if origin is not None and st[0] is not None and origin != st[0]:
                        stats['origin_changes'] += 1
                        if len(events) < max_events:
                            events.append({
                                'ts': ts, 'prefix': key,
                                'old_origin': st[0], 'new_origin': origin,
                                'peer_as': info['peer_as'],
                                'new_path': path[-8:] if len(path) > 8 else path,
                            })
                        st[0] = origin
                    elif st[0] is None:
                        st[0] = origin
    # top churn prefixes
    churn = sorted(state.items(), key=lambda kv: kv[1][1] + kv[1][2], reverse=True)[:20]
    stats['top_churn'] = [{'prefix': k, 'ann': v[1], 'wd': v[2], 'origin': v[0]}
                          for k, v in churn]
    return stats, events


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else \
        os.environ.get('BGP_UPDATES', os.path.join(_HERE, 'data', 'updates.mrt.gz'))
    stats, events = analyze(path)
    print(json.dumps(stats, indent=1))
    print(f'\n--- ORIGIN_CHANGE events: {len(events)} ---')
    for e in events[:30]:
        print(f"{e['prefix']:22s} AS{e['old_origin']} -> AS{e['new_origin']} "
              f"via peer AS{e['peer_as']} path={e['new_path']}")
    with open(os.path.join(_HERE, 'updates_report.json'), 'w') as f:
        json.dump({'stats': stats, 'origin_changes': events}, f, indent=1)


if __name__ == '__main__':
    main()
