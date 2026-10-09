"""Render QR matrices to PNG (PIL) and simulate damage/tampering.

Damage model: random module flips in the data region (what Reed-Solomon
protects) and contiguous patch pasting (sticker / occlusion / tamper).
"""
import random
from PIL import Image


def render(matrix, scale=10, quiet=4, path=None):
    """Render a 0/1 matrix to a PIL image (quiet zone included)."""
    dim = len(matrix)
    size = (dim + 2 * quiet) * scale
    img = Image.new("L", (size, size), 255)
    px = img.load()
    for r in range(dim):
        for c in range(dim):
            v = 0 if matrix[r][c] else 255
            for dr in range(scale):
                for dc in range(scale):
                    px[(c + quiet) * scale + dc, (r + quiet) * scale + dr] = v
    if path:
        img.save(path)
    return img


def flip_data_modules(matrix, is_func, n, seed=0):
    """Flip n random non-function modules (RS-protected region)."""
    rng = random.Random(seed)
    dim = len(matrix)
    cands = [(r, c) for r in range(dim) for c in range(dim) if not is_func[r][c]]
    out = [row[:] for row in matrix]
    for r, c in rng.sample(cands, min(n, len(cands))):
        out[r][c] ^= 1
    return out


def paste_patch(matrix, r0, c0, h, w, value=0):
    """Paste a contiguous patch (occlusion/tamper simulation)."""
    out = [row[:] for row in matrix]
    for r in range(r0, min(r0 + h, len(matrix))):
        for c in range(c0, min(c0 + w, len(matrix))):
            out[r][c] = value
    return out
