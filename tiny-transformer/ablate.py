#!/usr/bin/env python3
"""ablate.py — does layer norm actually matter? Train two tiny models,
one with layernorm monkeypatched to identity, and compare loss curves.

Run: python3 ablate.py   (takes ~10 min, prints both curves)
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import numpy as np
import tinygpt
from tinygpt import TinyGPT, ce_loss
from lab import get_data

def run(use_ln, steps=400):
    orig_fwd, orig_bwd = tinygpt.layernorm_fwd, tinygpt.layernorm_bwd
    if not use_ln:
        def ln_fwd_id(x, g, b, eps=1e-5): return x, (g.shape,)
        def ln_bwd_id(dout, cache):
            n = cache[0]
            return dout, np.zeros(n), np.zeros(n)
        tinygpt.layernorm_fwd = ln_fwd_id
        tinygpt.layernorm_bwd = ln_bwd_id
    tr, va, stoi, itos = get_data()
    V = len(stoi)
    m = TinyGPT(V, n_embd=48, n_layer=2, n_head=2, block=32, n_ff=96, seed=11)
    mt = {k: np.zeros_like(v) for k, v in m.P.items()}
    vt = {k: np.zeros_like(v) for k, v in m.P.items()}
    r = np.random.default_rng(5)
    losses = []
    t0 = time.time()
    for step in range(1, steps + 1):
        i = r.integers(0, len(tr) - 32, 32)
        xb = np.stack([tr[j:j + 32] for j in i])
        yb = np.stack([tr[j + 1:j + 33] for j in i])
        logits, cache = m.forward(xb)
        loss, dl = ce_loss(logits, yb)
        G = m.backward(dl, cache)
        gn = np.sqrt(sum((g ** 2).sum() for g in G.values()))
        if gn > 1.0:
            for k in G: G[k] *= 1.0 / gn
        for k in m.P:
            mt[k] = 0.9 * mt[k] + 0.1 * G[k]
            vt[k] = 0.999 * vt[k] + 0.001 * G[k] ** 2
            m.P[k] -= 3e-4 * (mt[k] / (1 - 0.9 ** step)) / (np.sqrt(vt[k] / (1 - 0.999 ** step)) + 1e-8)
        losses.append(float(loss))
    dt = time.time() - t0
    tinygpt.layernorm_fwd, tinygpt.layernorm_bwd = orig_fwd, orig_bwd
    return losses, dt

if __name__ == '__main__':
    l_ln, t_ln = run(True)
    l_no, t_no = run(False)
    print(f"\nwith layernorm    ({t_ln:5.1f}s): " +
          " ".join(f"{l_ln[i]:.3f}" for i in [0, 49, 99, 199, 299, 399]))
    print(f"without layernorm ({t_no:5.1f}s): " +
          " ".join(f"{l_no[i]:.3f}" for i in [0, 49, 99, 199, 299, 399]))
