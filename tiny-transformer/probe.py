#!/usr/bin/env python3
"""probe.py — look inside the trained tinyGPT.

1. Embedding geometry: which characters ended up near each other?
2. Attention maps: for a real snippet, where does each head look?
"""
import sys, os, pickle, numpy as np
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tinygpt import softmax

HERE = os.path.dirname(os.path.abspath(__file__))

def load():
    with open(os.path.join(HERE, 'ckpt.pkl'), 'rb') as f:
        c = pickle.load(f)
    return c

def neighbors():
    c = load(); P, stoi, itos = c['P'], c['stoi'], c['itos']
    E = P['tok_emb']
    n = np.linalg.norm(E, axis=1, keepdims=True) + 1e-9
    S = (E / n) @ (E / n).T
    print("== nearest neighbors in embedding space ==")
    for ch in ['A', 'e', ' ', '.', ',']:
        i = stoi[ch]
        top = np.argsort(-S[i])[:6]
        print(f"  {ch!r:4s} -> " + " ".join(f"{itos[j]!r}" for j in top if j != i))

def attention_maps(text="ROMEO:\nO, she doth teach"):
    c = load(); P, stoi, itos, cfg = c['P'], c['stoi'], c['itos'], c['cfg']
    n, L, h = cfg['n_embd'], cfg['n_layer'], cfg['n_head']
    idx = np.array([[stoi.get(ch, 0) for ch in text]])
    B, T = idx.shape
    x = P['tok_emb'][idx] + P['pos_emb'][:T][None, :, :]
    def ln(x, g, b):
        mu = x.mean(-1, keepdims=True); v = ((x - mu) ** 2).mean(-1, keepdims=True)
        return (x - mu) / np.sqrt(v + 1e-5) * g + b
    print(f"\n== attention maps for {text!r} ==")
    for i in range(L):
        x = ln(x, P[f'b{i}.ln1g'], P[f'b{i}.ln1b'])
        print(f"--- layer {i} (rows=query pos, cols=key pos; . =masked) ---")
        outs = []
        for hh in range(h):
            q = x @ P[f'b{i}.a{hh}q']; k = x @ P[f'b{i}.a{hh}k']; v = x @ P[f'b{i}.a{hh}v']
            s = q @ k.transpose(0, 2, 1) / np.sqrt(q.shape[-1])
            s[:, np.triu(np.ones((T, T), bool), 1)] = -1e10
            a = softmax(s)[0]
            outs.append(a @ v)
            # render: for each query position, show the top-2 attended keys
            chars = [repr(itos[stoi.get(ch, 0)]) for ch in text]
            print(f" head {hh}:")
            for t in range(T):
                top = np.argsort(-a[t])[:2]
                at = ", ".join(f"{chars[j]}({a[t,j]:.2f})" for j in top)
                print(f"   q[{t}]={chars[t]:6s} attends -> {at}")
        x = x + np.concatenate(outs, -1) @ P[f'b{i}.wo']
        x = x + np.maximum(0, ln(x, P[f'b{i}.ln2g'], P[f'b{i}.ln2b']) @ P[f'b{i}.fc'] + P[f'b{i}.fcb']) @ P[f'b{i}.proj'] + P[f'b{i}.projb']

if __name__ == '__main__':
    neighbors()
    attention_maps()
