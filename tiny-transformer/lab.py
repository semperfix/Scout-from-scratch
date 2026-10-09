#!/usr/bin/env python3
"""lab.py gradcheck | train | sample [ckpt]

gradcheck: finite-difference proof that every hand-derived backward pass
           (layernorm, attention, gelu, linear, embedding, full model) is correct.
train:     train TinyGPT on tinyshakespeare.txt with hand-rolled Adam.
sample:    generate text from a checkpoint.
"""
import sys, os, pickle, numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tinygpt import TinyGPT, ce_loss, softmax

HERE = os.path.dirname(os.path.abspath(__file__))

# ------------------------------------------------------- gradient check
def gradcheck():
    r = np.random.default_rng(0)
    V, T, B, n, L, h = 11, 5, 2, 8, 2, 2
    m = TinyGPT(V, n_embd=n, n_layer=L, n_head=h, block=T, n_ff=16, seed=0)
    idx = r.integers(0, V, (B, T))
    tgt = r.integers(0, V, (B, T))
    logits, cache = m.forward(idx)
    loss, dl = ce_loss(logits, tgt)
    G = m.backward(dl, cache)
    print(f"loss={loss:.6f}")
    worst, worstk, failed = 0, None, False
    eps = 1e-5
    for k in sorted(m.P):
        num = np.zeros_like(m.P[k])
        it = np.nditer(m.P[k], flags=['multi_index'])
        while not it.finished:
            ix = it.multi_index
            old = m.P[k][ix]
            m.P[k][ix] = old + eps
            lp, _ = ce_loss(m.forward(idx)[0], tgt)
            m.P[k][ix] = old - eps
            lm, _ = ce_loss(m.forward(idx)[0], tgt)
            m.P[k][ix] = old
            num[ix] = (lp - lm) / (2 * eps)
            it.iternext()
        denom = np.maximum(1e-8, np.abs(num) + np.abs(G[k]))
        rel = np.abs(num - G[k]) / denom
        abserr = np.abs(num - G[k])
        # flag only entries that are BOTH relatively wrong and meaningfully large
        # (near-zero gradient entries sit at the float64 noise floor ~1e-11)
        bad = (rel > 1e-4) & (abserr > 1e-9)
        w = rel.max()
        flag = f"  <-- CHECK ({bad.sum()} bad)" if bad.any() else ""
        failed = failed or bad.any()
        print(f"  {k:14s} max rel err {w:.2e}{flag}")
        if w > worst:
            worst, worstk = w, k
    # overall verdict: any entry both relatively wrong AND large in absolute terms?
    print(f"WORST rel err: {worstk} {worst:.2e}  ->  {'FAIL' if failed else 'PASS'}")
    return not failed

# ------------------------------------------------------------- training
def get_data():
    txt = open(os.path.join(HERE, 'tinyshakespeare.txt')).read()
    chars = sorted(set(txt))
    stoi = {c: i for i, c in enumerate(chars)}
    itos = {i: c for c, i in stoi.items()}
    data = np.array([stoi[c] for c in txt], dtype=np.int64)
    n = int(0.9 * len(data))
    return data[:n], data[n:], stoi, itos

def train(steps=1500, batch=32, block=48, lr=3e-4, ckpt='ckpt.pkl',
          n_embd=72, n_layer=3, n_head=3, n_ff=144, log_every=150,
          resume=None, save_every=300):
    tr, va, stoi, itos = get_data()
    V = len(stoi)
    m = TinyGPT(V, n_embd=n_embd, n_layer=n_layer, n_head=n_head,
                block=block, n_ff=n_ff, seed=1337)
    start = 1
    if resume and os.path.exists(os.path.join(HERE, resume)):
        with open(os.path.join(HERE, resume), 'rb') as f:
            c = pickle.load(f)
        m.P = c['P']; start = c.get('step', 0) + 1
        print(f"resumed from {resume} at step {start}", flush=True)
    # hand-rolled Adam
    mt = {k: np.zeros_like(v) for k, v in m.P.items()}
    vt = {k: np.zeros_like(v) for k, v in m.P.items()}
    b1, b2, eps = 0.9, 0.999, 1e-8
    r = np.random.default_rng(1)
    hist = []
    for step in range(start, steps + 1):
        i = r.integers(0, len(tr) - block, batch)
        xb = np.stack([tr[j:j + block] for j in i])
        yb = np.stack([tr[j + 1:j + block + 1] for j in i])
        logits, cache = m.forward(xb)
        loss, dl = ce_loss(logits, yb)
        G = m.backward(dl, cache)
        # gradient clip (global norm 1.0) — the standard stabilizer
        gn = np.sqrt(sum((g ** 2).sum() for g in G.values()))
        if gn > 1.0:
            for k in G: G[k] *= 1.0 / gn
        for k in m.P:
            mt[k] = b1 * mt[k] + (1 - b1) * G[k]
            vt[k] = b2 * vt[k] + (1 - b2) * G[k] ** 2
            mh = mt[k] / (1 - b1 ** step); vh = vt[k] / (1 - b2 ** step)
            m.P[k] -= lr * mh / (np.sqrt(vh) + eps)
        hist.append(float(loss))
        if step % log_every == 0 or step == 1:
            # quick validation loss
            i2 = r.integers(0, len(va) - block, 32)
            xv = np.stack([va[j:j + block] for j in i2])
            yv = np.stack([va[j + 1:j + block + 1] for j in i2])
            vl, _ = ce_loss(m.forward(xv)[0], yv)
            print(f"step {step:5d}  train {loss:.4f}  val {vl:.4f}", flush=True)
        if step % save_every == 0:
            with open(os.path.join(HERE, ckpt), 'wb') as f:
                pickle.dump({'P': m.P, 'cfg': m.cfg, 'stoi': stoi, 'itos': itos,
                             'hist': hist, 'step': step}, f)
    with open(os.path.join(HERE, ckpt), 'wb') as f:
        pickle.dump({'P': m.P, 'cfg': m.cfg, 'stoi': stoi, 'itos': itos,
                     'hist': hist, 'step': steps}, f)
    print(f"saved {ckpt}; final train loss {hist[-1]:.4f}")
    return m, stoi, itos

# ------------------------------------------------------------- sampling
def sample(ckpt='ckpt.pkl', n_chars=500, temp=0.8, prompt="ROMEO:\n"):
    with open(os.path.join(HERE, ckpt), 'rb') as f:
        c = pickle.load(f)
    m = TinyGPT(c['cfg']['V']); m.P = c['P']; m.cfg = c['cfg']
    stoi, itos = c['stoi'], c['itos']
    block = c['cfg']['block']
    idx = np.array([[stoi.get(ch, 0) for ch in prompt]], dtype=np.int64)
    r = np.random.default_rng(7)
    out = list(prompt)
    for _ in range(n_chars):
        x = idx[:, -block:]
        logits, _ = m.forward(x)
        p = softmax(logits[0, -1] / temp)
        nxt = r.choice(len(p), p=p)
        out.append(itos[nxt])
        idx = np.concatenate([idx, [[nxt]]], axis=1)
    print(''.join(out))

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'gradcheck'
    if cmd == 'gradcheck':
        ok = gradcheck(); sys.exit(0 if ok else 1)
    elif cmd == 'train':
        train()
    elif cmd == 'sample':
        sample(*(sys.argv[2:]))
