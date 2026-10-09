"""Synthetic photo-like test images (numpy). Smooth gradients + gaussian noise
mimic natural images closely enough that LSB detectors behave realistically.
"""
import numpy as np


def photo_like(w, h, seed=0, smooth=6.0, noise=6.0):
    """Low-frequency 'scene' via blurred random blobs + fine sensor noise."""
    rng = np.random.default_rng(seed)
    coarse = rng.normal(0, 1, (max(1, h // 16), max(1, w // 16), 3))
    # crude bilinear upsample of the coarse field
    yy = np.linspace(0, coarse.shape[0] - 1, h)
    xx = np.linspace(0, coarse.shape[1] - 1, w)
    y0 = np.clip(yy.astype(int), 0, coarse.shape[0] - 2)
    x0 = np.clip(xx.astype(int), 0, coarse.shape[1] - 2)
    fy = (yy - y0)[:, None, None]
    fx = (xx - x0)[None, :, None]
    c00, c01 = coarse[y0][:, x0], coarse[y0][:, x0 + 1]
    c10, c11 = coarse[y0 + 1][:, x0], coarse[y0 + 1][:, x0 + 1]
    base = (c00 * (1 - fx) + c01 * fx) * (1 - fy) + (c10 * (1 - fx) + c11 * fx) * fy
    img = 128 + smooth * 8 * base + rng.normal(0, noise, (h, w, 3))
    return np.clip(img, 0, 255).astype(np.uint8)


def to_pixels(arr):
    h, w, _ = arr.shape
    return [[tuple(int(v) for v in arr[y, x]) for x in range(w)] for y in range(h)]


def flat_image(w, h, color=(120, 130, 140), noise=1.0, seed=1):
    rng = np.random.default_rng(seed)
    img = np.full((h, w, 3), color) + rng.normal(0, noise, (h, w, 3))
    return np.clip(img, 0, 255).astype(np.uint8)
