# Steganography & Steganalysis (from scratch)

Hide data in images, then detect it statistically. Implements spatial LSB
embedding (sequential and password-seeded spread placement) and DCT-domain
embedding (Jsteg-style and F5-style), plus the classic statistical attacks
against them: chi-square PoV scan, RS analysis (Fridrich–Goljan–Du), and a
calibration attack. The triage CLI runs three detectors over any 24-bit BMP and
prints a verdict. No PIL, no OpenCV, no crypto libs.

## Dependencies

- **Python 3** (3.10+ recommended)
- **numpy** (`pip install numpy`) — needed for `dctstego.py`, `testimg.py`, and
  `test_stego.py`. The core triage path (`bmp.py`, `lsb.py`, `steganalysis.py`,
  `stegdetect.py`) is **stdlib only**.

## How to run

**Triage a suspicious BMP** (entry point `stegdetect.py`):

```bash
python3 stegdetect.py suspect.bmp
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `SUSPICIOUS` / `STEGO-LIKELY`).

**Hide and extract data yourself:**

```python
from bmp import make_bmp, read_bmp, flatten, unflatten
from lsb import embed, extract

rows = ...  # 24-bit RGB rows, list of lists of (r, g, b) tuples
embed(rows, b"secret message", mode="sequential")   # or mode="spread", password="pw"
open("stego.bmp", "wb").write(make_bmp(w, h, rows))

w, h, rows = read_bmp(open("stego.bmp", "rb").read())
print(extract(flatten(rows)))                        # b"secret message"
```

**Run the validation battery:**

```bash
python3 test_stego.py    # 37 deterministic checks (needs numpy)
```

## Example

```bash
$ python3 stegdetect.py suspect.bmp
file: suspect.bmp  (128x128, 49152 channel bytes)
chi-square scan (window -> P(embedded)):
   20.0%  1.0000
   40.0%  1.0000
   60.0%  0.0012
   ...
RS embedding-rate estimate R/G/B: [0.0, 0.0, 0.0]
smooth-region LSB agreement: 0.486 (clean ~0.70; embedded -> ~0.60)
VERDICT: STEGO-LIKELY -- chi-square P(embedded)=1.000; LSB plane noisy in smooth regions (0.49)
```

## Key learnings

- **Every detector has a blind spot shaped exactly like the embedder it wasn't
  designed for.** Chi-square is blind to spread embedding by construction; F5
  (decrement-|c| with shrinkage) is immune to chi-square at *every* payload size
  because it shifts the histogram toward even values instead of equalizing PoV
  pairs — but the calibration attack catches F5 where chi-square is blind.
- **RS analysis fails honestly.** On sequential embedding the model violation makes
  the quadratic's discriminant go negative → returns 0.0 (no estimate) instead of
  a confident wrong number. The patent text (US6831991B2), not tutorials, settled
  the d1/d_−0 mapping — and the root taken is the one with smaller *absolute*
  value, not the smaller root.
- **Chi-square localizes payload end.** P(embedded) = 1.0 inside the payload
  region and collapses past the end — it shows *where* the payload stops, not
  just that one exists.
- **BMP rows are bottom-up.** Writer wrote top-first, reader read bottom-up —
  round-trip "worked" on dims but pixels were vertically flipped. Caught by
  asserting pixel equality, not just dims.

## Files

| File | What it does |
|---|---|
| `stegdetect.py` | **Entry point**: triage CLI — chi-square scan + RS + LSB stats + verdict for any 24-bit BMP |
| `bmp.py` | Hand-rolled 24-bit uncompressed BMP reader/writer (BGR order, row padding, bottom-up rows) |
| `lsb.py` | LSB embed/extract: length + CRC32 framing; `sequential` and password-seeded `spread` (Fisher–Yates) placement |
| `steganalysis.py` | Chi-square PoV attack (hand-written regularized gamma for p-values), RS analysis (Fridrich–Goljan–Du), LSB-plane statistics |
| `dctstego.py` | Hand-rolled 8×8 DCT-II/IDCT, IJG luminance quantization, F5-style and Jsteg-style embedding, chi-square on coefficients, calibration attack (lite "Breaking F5") |
| `testimg.py` | Photo-like synthetic covers (fractal texture octaves + sensor noise) |
| `test_stego.py` | 37-check battery, all deterministic |

## Limitations

- Spatial detectors assume uncompressed 24-bit input (BMP). Real-world JPEG
  input would need a decoder; the DCT module demonstrates the JPEG-domain math
  on synthetic coefficient arrays instead.
- RS assumes uniform embedding and small initial bias; real photos satisfy the
  assumptions better than synthetics.
- The `spread` PRNG is `random.Random(password)` — obfuscation, not crypto.
- Calibration attack is lite (odd/even balance only, not the full least-squares
  β fit of "Breaking F5").
