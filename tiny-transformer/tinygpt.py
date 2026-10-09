#!/usr/bin/env python3
"""tinyGPT from scratch — pure numpy, no torch.

Every forward op has a hand-derived backward pass. The full model
gradient is proven correct by finite-difference gradient checking,
then a real GPT (embeddings + causal multi-head attention + MLP +
layer norm + residuals) is trained on Tiny Shakespeare with hand-rolled Adam.

Usage:
  python3 tinygpt.py gradcheck        # prove analytic grads == numeric grads
  python3 tinygpt.py train            # train on tinyshakespeare.txt
  python3 tinygpt.py sample [ckpt]    # generate text from checkpoint
"""
import sys, os, pickle, numpy as np

rng = np.random.default_rng(1337)

# ---------------------------------------------------------------- core ops
def softmax(x):
    e = np.exp(x - x.max(axis=-1, keepdims=True))
    return e / e.sum(axis=-1, keepdims=True)

def gelu(x):
    # tanh approximation (Hendrycks & Gimpel)
    c = np.sqrt(2 / np.pi)
    inner = c * (x + 0.044715 * x ** 3)
    t = np.tanh(inner)
    return 0.5 * x * (1 + t)

def gelu_bwd(x, dout):
    c = np.sqrt(2 / np.pi)
    inner = c * (x + 0.044715 * x ** 3)
    t = np.tanh(inner)
    sech2 = 1 - t * t
    d_inner = c * (1 + 3 * 0.044715 * x ** 2)
    return dout * (0.5 * (1 + t) + 0.5 * x * sech2 * d_inner)

def layernorm_fwd(x, g, b, eps=1e-5):
    mu = x.mean(axis=-1, keepdims=True)
    xc = x - mu
    var = (xc ** 2).mean(axis=-1, keepdims=True)
    inv = 1.0 / np.sqrt(var + eps)
    xh = xc * inv
    return xh * g + b, (x, xh, inv, g)

def layernorm_bwd(dout, cache):
    x, xh, inv, g = cache
    B, T, n = dout.shape
    dg = (dout * xh).sum(axis=(0, 1))
    db = dout.sum(axis=(0, 1))
    dxh = dout * g
    dxc = dxh * inv
    dvar = (dxh * (x - x.mean(axis=-1, keepdims=True)) * -0.5 * inv ** 3).sum(axis=-1, keepdims=True)
    dmu = (-dxc).sum(axis=-1, keepdims=True) + dvar * (-2 * (x - x.mean(axis=-1, keepdims=True))).mean(axis=-1, keepdims=True)
    dx = dxc + dvar * 2 * (x - x.mean(axis=-1, keepdims=True)) / n + dmu / n
    return dx, dg, db

def linear_fwd(x, W, b):
    return x @ W + b, (x, W)

def linear_bwd(dout, cache):
    x, W = cache
    dx = dout @ W.T
    dW = x.reshape(-1, x.shape[-1]).T @ dout.reshape(-1, dout.shape[-1])
    db = dout.sum(axis=tuple(range(dout.ndim - 1)))
    return dx, dW, db

def causal_attn_fwd(x, Wq, Wk, Wv):
    """single-head causal self-attention. x:(B,T,n) -> out:(B,T,d)"""
    B, T, n = x.shape
    d = Wq.shape[1]
    q = x @ Wq; k = x @ Wk; v = x @ Wv            # (B,T,d)
    s = q @ k.transpose(0, 2, 1) / np.sqrt(d)     # (B,T,T)
    mask = np.triu(np.ones((T, T), bool), k=1)
    s = np.where(mask, -1e10, s)
    a = softmax(s)
    out = a @ v
    return out, (x, q, k, v, s, a, Wq, Wk, Wv)

def causal_attn_bwd(dout, cache):
    x, q, k, v, s, a, Wq, Wk, Wv = cache
    B, T, d = dout.shape
    scale = 1.0 / np.sqrt(d)
    dv = a.transpose(0, 2, 1) @ dout              # (B,T,d)
    da = dout @ v.transpose(0, 2, 1)             # (B,T,T)
    # softmax backward: ds = a*(da - sum(a*da))
    ds = a * (da - (a * da).sum(axis=-1, keepdims=True))
    dq = (ds @ k) * scale
    dk = (ds.transpose(0, 2, 1) @ q) * scale
    dx = dq @ Wq.T + dk @ Wk.T + dv @ Wv.T
    dWq = np.einsum('bti,btj->ij', x, dq)
    dWk = np.einsum('bti,btj->ij', x, dk)
    dWv = np.einsum('bti,btj->ij', x, dv)
    return dx, dWq, dWk, dWv

# ---------------------------------------------------------------- model
class TinyGPT:
    def __init__(self, V, n_embd=96, n_layer=3, n_head=3, block=64, n_ff=None, seed=1337):
        assert n_embd % n_head == 0
        self.cfg = dict(V=V, n_embd=n_embd, n_layer=n_layer, n_head=n_head,
                        block=block, n_ff=n_ff or 4 * n_embd)
        r = np.random.default_rng(seed)
        n, L, h, F = n_embd, n_layer, n_head, self.cfg['n_ff']
        d = n // h
        P = {}
        P['tok_emb'] = r.normal(0, 0.02, (V, n))
        P['pos_emb'] = r.normal(0, 0.02, (block, n))
        for i in range(L):
            P[f'b{i}.ln1g'] = np.ones(n);  P[f'b{i}.ln1b'] = np.zeros(n)
            P[f'b{i}.ln2g'] = np.ones(n);  P[f'b{i}.ln2b'] = np.zeros(n)
            for hh in range(h):
                for nm in ('q', 'k', 'v'):
                    P[f'b{i}.a{hh}{nm}'] = r.normal(0, 0.02, (n, d))
            P[f'b{i}.wo'] = r.normal(0, 0.02 / np.sqrt(2 * L), (n, n))
            P[f'b{i}.fc'] = r.normal(0, 0.02, (n, F))
            P[f'b{i}.fcb'] = np.zeros(F)
            P[f'b{i}.proj'] = r.normal(0, 0.02 / np.sqrt(2 * L), (F, n))
            P[f'b{i}.projb'] = np.zeros(n)
        P['lnfg'] = np.ones(n); P['lnfb'] = np.zeros(n)
        P['head'] = r.normal(0, 0.02, (n, V)); P['headb'] = np.zeros(V)
        self.P = P

    def forward(self, idx):
        """idx:(B,T) -> logits:(B,T,V), cache"""
        P, c = self.P, self.cfg
        B, T = idx.shape
        n, L, h = c['n_embd'], c['n_layer'], c['n_head']
        x = P['tok_emb'][idx] + P['pos_emb'][:T][None, :, :]
        cache = {'tok_idx': idx, 'x0': x}
        for i in range(L):
            # attention sub-block
            xln, c1 = layernorm_fwd(x, P[f'b{i}.ln1g'], P[f'b{i}.ln1b'])
            heads, ac = [], []
            for hh in range(h):
                o, cc = causal_attn_fwd(xln, P[f'b{i}.a{hh}q'], P[f'b{i}.a{hh}k'], P[f'b{i}.a{hh}v'])
                heads.append(o); ac.append(cc)
            cat = np.concatenate(heads, axis=-1)          # (B,T,n)
            ao, cwo = linear_fwd(cat, P[f'b{i}.wo'], np.zeros(n))
            x = x + ao
            cache[f'b{i}'] = (c1, ac, cat, cwo, xln)
            # MLP sub-block
            xln2, c2 = layernorm_fwd(x, P[f'b{i}.ln2g'], P[f'b{i}.ln2b'])
            f, cf = linear_fwd(xln2, P[f'b{i}.fc'], P[f'b{i}.fcb'])
            g = gelu(f)
            p, cp = linear_fwd(g, P[f'b{i}.proj'], P[f'b{i}.projb'])
            x = x + p
            cache[f'b{i}m'] = (c2, cf, f, cp, xln2)
        xf, clf = layernorm_fwd(x, P['lnfg'], P['lnfb'])
        logits, cl = linear_fwd(xf, P['head'], P['headb'])
        cache['top'] = (clf, cl, xf)
        return logits, cache

    def backward(self, dlogits, cache):
        P, c = self.P, self.cfg
        n, L, h = c['n_embd'], c['n_layer'], c['n_head']
        G = {k: np.zeros_like(v) for k, v in P.items()}
        clf, cl, xf = cache['top']
        dxf, dWh, dbh = linear_bwd(dlogits, cl)
        G['head'] += dWh; G['headb'] += dbh
        dx, dlnfg, dlnfb = layernorm_bwd(dxf, clf)
        G['lnfg'] += dlnfg; G['lnfb'] += dlnfb
        for i in reversed(range(L)):
            # MLP backward
            c2, cf, f, cp, xln2 = cache[f'b{i}m']
            dp, dWpr, dbpr = linear_bwd(dx, cp)
            G[f'b{i}.proj'] += dWpr; G[f'b{i}.projb'] += dbpr
            dg = gelu_bwd(f, dp)
            dxln2, dWfc, dbfc = linear_bwd(dg, cf)
            G[f'b{i}.fc'] += dWfc; G[f'b{i}.fcb'] += dbfc
            dxmlp, dln2g, dln2b = layernorm_bwd(dxln2, c2)
            G[f'b{i}.ln2g'] += dln2g; G[f'b{i}.ln2b'] += dln2b
            dx = dx + dxmlp                      # residual: grad flows to both branches
            # attention backward
            c1, ac, cat, cwo, xln = cache[f'b{i}']
            dcat, dWo, _ = linear_bwd(dx, cwo)
            G[f'b{i}.wo'] += dWo
            dxln = np.zeros_like(xln)
            for hh in range(h):
                dhead = dcat[:, :, hh * (n // h):(hh + 1) * (n // h)]
                dxi, dWq, dWk, dWv = causal_attn_bwd(dhead, ac[hh])
                dxln += dxi
                G[f'b{i}.a{hh}q'] += dWq; G[f'b{i}.a{hh}k'] += dWk; G[f'b{i}.a{hh}v'] += dWv
            dxa, dln1g, dln1b = layernorm_bwd(dxln, c1)
            G[f'b{i}.ln1g'] += dln1g; G[f'b{i}.ln1b'] += dln1b
            dx = dx + dxa
        # embeddings
        idx = cache['tok_idx']
        B, T = idx.shape
        G['pos_emb'][:T] += dx.sum(axis=0)
        np.add.at(G['tok_emb'], idx, dx)
        return G

def ce_loss(logits, targets):
    """softmax cross-entropy; returns loss and dlogits"""
    B, T, V = logits.shape
    lse = np.log(np.exp(logits - logits.max(-1, keepdims=True)).sum(-1))
    lp = logits - logits.max(-1, keepdims=True) - lse[..., None]
    loss = -lp[np.arange(B)[:, None], np.arange(T), targets].mean()
    dlogits = np.exp(lp)
    dlogits[np.arange(B)[:, None], np.arange(T), targets] -= 1
    return loss, dlogits / (B * T)
