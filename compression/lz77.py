"""LZ77 factorization from scratch (the front half of DEFLATE).

Tokenizes a byte string into literals and (distance, length) matches using a
hash-chain match finder like zlib's: positions indexed by 3-byte hash, chains
walked up to a limit. Greedy (non-lazy) parsing.

Emits tokens: ('lit', byte) or ('match', distance, length).
"""
MIN_MATCH = 3
MAX_MATCH = 258
WINDOW = 32768
HASH_BITS = 15
MAX_CHAIN = 256


def _hash3(data, i):
    return ((data[i] << 10) ^ (data[i + 1] << 5) ^ data[i + 2]) & ((1 << HASH_BITS) - 1)


def tokenize(data):
    """Greedy LZ77 factorization of data -> list of tokens."""
    n = len(data)
    head = [None] * (1 << HASH_BITS)
    prev = [None] * n
    tokens = []
    pos = 0
    while pos < n:
        best_len, best_dist = 0, 0
        if pos + MIN_MATCH <= n:
            h = _hash3(data, pos)
            cand = head[h]
            chain = 0
            limit = max(pos - WINDOW, 0)
            max_len = min(MAX_MATCH, n - pos)
            while cand is not None and cand >= limit and chain < MAX_CHAIN:
                chain += 1
                dist = pos - cand
                if dist and dist <= WINDOW:
                    length = 0
                    while length < max_len and data[cand + length] == data[pos + length]:
                        length += 1
                    if length > best_len:
                        best_len, best_dist = length, dist
                        if length == max_len:
                            break
                cand = prev[cand]
            # insert pos into the chain
            prev[pos] = head[h]
            head[h] = pos
        if best_len >= MIN_MATCH:
            tokens.append(('match', best_dist, best_len))
            for k in range(1, best_len):
                q = pos + k
                if q + MIN_MATCH <= n:
                    hh = _hash3(data, q)
                    prev[q] = head[hh]
                    head[hh] = q
            pos += best_len
        else:
            tokens.append(('lit', data[pos]))
            pos += 1
    return tokens


def detokenize(tokens):
    out = bytearray()
    for tok in tokens:
        if tok[0] == 'lit':
            out.append(tok[1])
        else:
            _, dist, length = tok
            for _ in range(length):
                out.append(out[-dist])  # overlapping copy is correct LZ77 behavior
    return bytes(out)


def stats(tokens):
    nlit = sum(1 for t in tokens if t[0] == 'lit')
    nmatch = len(tokens) - nlit
    mlen = sum(t[2] for t in tokens if t[0] == 'match')
    return {'tokens': len(tokens), 'literals': nlit, 'matches': nmatch,
            'match_bytes_covered': mlen}
