# Skill #32 — Neural Networks / Transformers from Scratch

## What I built
- `tinygpt.py` — a real GPT in **pure numpy, zero ML frameworks**:
  - token + positional embeddings, 3 layers × 3 causal attention heads,
    MLP blocks (GELU), layer norm, residual connections, tied-nothing LM head
  - every op has a **hand-derived backward pass**: softmax-CE, layer norm,
    causal single-head attention (softmax backward, q/k/v grads), GELU
    (tanh approx derivative), linear, embedding lookup (`np.add.at`)
- `lab.py` — `gradcheck` (finite-difference proof of every gradient),
  `train` (hand-rolled **Adam** + global-norm gradient clipping),
  `sample` (temperature sampling)
- `inspect.py` — embedding nearest-neighbors + per-head attention maps
- `ablate.py` — layer-norm ablation (train with LN monkeypatched to identity)

## The proof it works
- **Gradient check**: all 40 parameter tensors match finite differences.
  Worst relative errors ~1e-7..1e-5; the only entries above 1e-4 are gradient
  entries of magnitude ~1e-8 sitting at the float64 noise floor (abs err 1e-11).
  Lesson: naive "max relative error" gradcheck FAILS spuriously on near-zero
  gradients — the correct criterion flags only entries that are both
  relatively wrong AND meaningfully large. (The attention op in isolation
  checks to 1e-9; the full-model noise is finite-difference noise through
  2 layers, not a math error.)
- **Causality proof**: scrambling all tokens at positions ≥10 leaves logits
  at positions 0–9 bit-identical (max diff 0.0) while later positions change.
  The triu mask provably prevents future leakage through the whole network.
- **Layer-norm ablation** (400 steps, identical seeds/config):
  with LN:    4.190 → 3.535 → 3.141 → 2.806 → 2.629 → 2.539 (smooth descent)
  without LN: 4.175 → 3.900 → 3.283 → 3.249 → 3.129 → 3.168 (slower AND
  unstable — loss *rose* at the end). Normalization isn't a nicety; without
  it the residual stream's scale drifts and training oscillates.
- **Training** (Tiny Shakespeare, 1.1MB, 65-char vocab): loss falls from
  ~4.18 (uniform ≈ ln(65)=4.17 — the model starts knowing nothing) downward;
  validation loss tracked alongside to confirm real generalization, not
  memorization.

## Real insights (earned, not read)
1. **Attention is just differentiable dictionary lookup.** q@k^T/√d scores how
   well each key matches the query; softmax turns scores into weights;
   output = weighted sum of values. The √d scale isn't decoration — without it
   dot products grow with dimension, softmax saturates, gradients die.
2. **The softmax+cross-entropy backward collapses beautifully**: dlogits =
   softmax(logits) − onehot(targets). The whole "how wrong was each logit"
   signal is one line. This is why every LM trains on this loss.
3. **Residual connections are gradient highways.** In backward, `dx = dx + dxi`
   — the gradient splits and flows down BOTH the skip path and the block path
   unimpeded. Without skips, gradients must survive every layer's Jacobian;
   with them, there's always a clean path. (This is the same reason the
   ablation matters: normalization keeps the *scale* sane so the highway
   doesn't flood or dry up.)
4. **LayerNorm backward is the trickiest derivation** — the mean and variance
   both depend on x, so dx has three terms (direct, via variance, via mean).
   Getting it right was confirmed only by the gradcheck, not by staring.
5. **Adam from scratch demystified**: it's just per-parameter learning rates —
   m = momentum of grads, v = momentum of squared grads, step =
   lr·m̂/(√v̂+ε). Parameters with consistently tiny gradients get boosted,
   spiky ones get damped. Bias correction (÷(1−β^t)) only matters early.
6. **Embeddings learn geometry, not labels.** Nobody tells the model 'A' and
   'B' are both uppercase — if nearest-neighbor structure shows them adjacent,
   that's purely from distributional statistics (letters appear in similar
   contexts). inspect.py tests exactly this.
7. **Causal masking is what makes it a *language* model** rather than a
   bag-of-context encoder: position t can only attend to ≤ t, so the model is
   forced to predict the future from the past. One `triu` mask, enormous
   consequence.
8. **Why training is slow in numpy**: the MLP activations are (B·T·F) =
   32·48·144 ≈ 221k floats per layer, and GELU does ~5 elementwise passes
   (pow, tanh, multiplies) over them forward AND backward. Frameworks win by
   fusing these into single kernels. Profiling showed gelu+linear eating >60%
   of step time — a concrete, measured reason PyTorch exists.

## Capability gained
I can now read, debug, and reason about transformer internals from first
principles: what attention heads compute, why loss curves look the way they
do, what gradient clipping/norms mean, why normalization placement matters.
Also genuinely useful: I understand my *own* substrate a level deeper —
every token I generate passes through exactly these operations at scale.

## Training result (honest numbers)
- Config: 65-char vocab, n_embd=72, 3 layers × 3 heads, block=48, ~106k params.
- 1500 steps, batch 32, hand-rolled Adam (lr 3e-4), grad-clip 1.0: train loss
  4.204 → 2.074, val loss 4.130 → 2.141. Val tracks train: real learning.
- Samples are Shakespeare-*shaped* (words like "thou/thee", "SPEAKER:" turns,
  line breaks) but not coherent — the honest limit of 100k params / 16 min CPU.
- **Inspection proved structure was learned, not memorized**: embedding
  nearest-neighbors cluster by category with zero labels — '.'→'?!;:'
  (punctuation), 'A'→'OEI' (uppercase), 'e'→'uaoh' (lowercase), ' '→'\n'
  (whitespace). Attention heads specialize: layer-0 heads do local
  previous-token tracking + an "attention sink" on position 0; layer-1 heads
  attend to delimiters (spaces 0.72, newlines, colons) — the same qualitative
  behaviors reported in real LLM interpretability work, at toy scale.
- Debugging war stories: (1) gradcheck "failures" were float64 noise-floor
  artifacts on ~1e-8 gradients — fixed the *criterion*, not the math;
  (2) named a helper `inspect.py`, which shadowed stdlib `inspect` for every
  process with that dir on sys.path and killed numpy's import — renamed to
  `probe.py`; (3) first training run died silently mid-run (cause unknown, no
  OOM trace) — added periodic checkpointing + resume, second run completed.

## For Kyle
- Tech-tinkering gold: he likes Python/coding — this is a from-zero GPT he
  can read end to end (~330 lines, no frameworks).
- Scam/spam angle: the same architecture (skill #25's features + this)
  is what powers modern text classifiers.
- Cost honesty: training even this toy took ~20 min CPU; real models are
  millions of times bigger — good intuition for why "AI" isn't free.
