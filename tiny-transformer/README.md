# Tiny Transformer — a GPT from Scratch in Pure NumPy

A real, working GPT implemented from zero with **no ML frameworks** — just
numpy. `tinygpt.py` (~330 lines) has token + positional embeddings, 3 layers ×
3 causal attention heads, GELU MLPs, layer norm, and residual connections, with
every operation's backward pass hand-derived by hand (softmax-CE, layer norm,
causal single-head attention, GELU, linear, embedding lookup).

`lab.py` provides the machinery around it: `gradcheck` (finite-difference proof
of all 40 parameter-tensor gradients), `train` (hand-rolled **Adam** + global
gradient clipping), and `sample` (temperature sampling). Trained 1500 steps on
Tiny Shakespeare (1.1 MB, 65-char vocab): train loss 4.20 → 2.07, validation
tracks training (real generalization), and samples come out Shakespeare-shaped
("thou/thee", `SPEAKER:` turns) — the honest limit of ~106k params on CPU.

## Dependencies

**numpy only** (e.g. 1.26.4). No torch/tensorflow. No internet needed after
install — `pip install numpy` once.

## How to run

```
python3 lab.py gradcheck        # finite-difference proof of every gradient (40 tensors)
python3 lab.py train            # train on tinyshakespeare.txt, writes ckpt.pkl (CPU, ~20 min)
python3 lab.py sample ckpt.pkl  # temperature-sample from a checkpoint
```

`ablate.py` runs the layer-norm ablation (train with LN monkeypatched to
identity); `probe.py` inspects embeddings (nearest neighbors) and per-head
attention maps.

## Usage example

```python
import numpy as np
from tinygpt import TinyGPT

m = TinyGPT(65, n_embd=24, n_head=2, n_layer=1, block=16)
x = np.random.randint(0, 65, (2, 16))   # (batch, time) token ids
logits, cache = m.forward(x)            # logits: (2, 16, 65)
```

## Key learnings

- **Attention is differentiable dictionary lookup.** q·kᵀ/√d scores each key
  against the query, softmax makes the weights, output = weighted sum of values.
  The √d scale isn't decoration: without it dot products grow with dimension,
  softmax saturates, and gradients die.
- **softmax + cross-entropy backward is one line**: `dlogits = softmax(logits) −
  onehot(target)`. The whole "how wrong was each logit" signal collapses into a
  single expression — this is why every language model trains on this loss.
- **Residual connections are gradient highways.** In backward, `dx = dx + dxi` —
  gradients flow down both the skip and the block path unimpeded. Layer norm
  keeps the scale sane so the highway doesn't flood or dry up (ablation proved
  it: no-LN training is slower *and* unstable, loss rising at the end).
- **The gradcheck criterion matters more than the math.** Naive "max relative
  error" gradcheck fails spuriously on ~1e-8 gradients sitting at the float64
  noise floor (abs err 1e-11). Only flag entries that are *both* relatively wrong
  *and* meaningfully large — the attention op in isolation checks to 1e-9.

## Files

- `tinygpt.py` — the model + all hand-derived backward passes
- `lab.py` — `gradcheck`, `train` (Adam + grad clipping), `sample`
- `probe.py` — embedding nearest-neighbors + per-head attention maps
- `ablate.py` — layer-norm ablation experiment
- `tinyshakespeare.txt` — training corpus (1.1 MB)
- `ckpt.pkl` — trained checkpoint (~1 MB: weights + `stoi`/`itos`)
- `LEARNINGS.md` — the full expedition writeup with honest numbers
