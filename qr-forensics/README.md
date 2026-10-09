# QR Code Forensics & Quishing Triage

A complete QR-code stack built from scratch with zero QR libraries: the Galois-field
math, a matrix encoder/decoder, an image-level detector, and a quishing (QR-phishing)
triage tool. Decode suspicious QR codes locally — nothing is ever uploaded anywhere —
and get a verdict on whether the payload is CLEAN, WORTH-A-LOOK, or SUSPICIOUS.

The decoder also reports an error-correction damage meter (`ec_corrected` vs
`ec_capacity`), which works as a quantitative tamper indicator: a small sticker over
the data corrects a predictable number of codewords.

## Dependencies

- **Python 3** (3.10+ recommended)
- **Pillow** (`pip install pillow`) — image loading in `qr_detect.py`, PNG rendering in `qr_render.py`
- **numpy** (`pip install numpy`) — image scan-line math in `qr_detect.py`

The codec itself (`gf256.py`, `rs.py`, `qr_tables.py`, `qr_codec.py`) is pure stdlib;
only the image side needs the two pip packages.

## How to run

There is no argparse CLI — the entry point is the `triage_image` / `print_report`
API in `qr_triage.py`:

**Triage a suspicious QR image:**

```python
from qr_triage import triage_image, print_report
print_report(triage_image("suspicious-qr.png"))
```

**Encode and render your own QR codes:**

```python
from qr_codec import encode
from qr_render import render
matrix, info = encode(b"https://example.com", "M")   # versions 1-10
render(matrix, scale=10, quiet=4, path="out.png")
```

**Run the validation battery:**

```bash
python3 test_qr.py    # 27 checks: GF(2^8) properties, RS fuzz, round-trips, cross-validation
```

## Example

```python
from qr_triage import triage_image, print_report

report = triage_image("suspect.png")
print_report(report)
# verdict: WORTH-A-LOOK  (score 3)
# kind: url  v3-M mask 0
# payload: https://paypa1-login.top/signin
#   [medium] high-abuse TLD
# error correction: absorbed 0/13 (margin 13)
```

Payload kinds detected: URL, WiFi config, mailto, bitcoin, vCard, plain text.
Quishing heuristics flag URL shorteners, high-abuse TLDs (`.top`, `.zip`, `.mov`, …),
credential-in-URL patterns, and punycode.

## Key learnings

- **Cross-validate, don't self-round-trip.** Self-consistency proves nothing: the
  encoder's finder pattern was wrong (1-module center instead of 3×3) and only
  bit-for-bit diffing against segno's independent encoder caught it.
- **Reed-Solomon conventions bite everyone.** Whether your polynomial list is
  big-endian or little-endian in x changes which way "append zeros" shifts — be
  explicit that the public list is transmission order and the internal polynomial
  is its reverse.
- **QR uses GF(2⁸) with polynomial 0x11D, not the AES field 0x11B.** Different
  field, so AES test vectors don't apply — caught by asserting field-internal
  properties first.
- **Data fakes the 1:1:3:1:1 finder signature constantly.** Real finders are found
  by geometry (right-isosceles triple) *plus* module-size agreement — weighting both
  beats a tiny perfect fake triangle with dozens of scan hits.

## Files

| File | What it does |
|---|---|
| `qr_triage.py` | **Entry point**: payload classification (URL/WiFi/mailto/bitcoin/…) + quishing heuristics → CLEAN / WORTH-A-LOOK / SUSPICIOUS |
| `qr_codec.py` | Matrix builder/encoder (mode & version selection, interleaving, mask-penalty choice) and matrix decoder |
| `qr_detect.py` | Image → matrix: Otsu thresholding, 1:1:3:1:1 finder scan + vertical cross-check, right-triangle triple selection, alignment-pattern search, 4-point homography, per-module sampling |
| `qr_render.py` | PIL rendering + damage simulation (random flips, patch pasting) |
| `qr_tables.py` | Version/EC-block tables (v1–10), modes, masks, format/version BCH |
| `gf256.py` | GF(2⁸) arithmetic (QR polynomial 0x11D) |
| `rs.py` | Reed-Solomon encode + full errors-only decode (Berlekamp-Massey, Chien search, Forney); corrects ⌊nsym/2⌋ errors, fails loudly beyond that |
| `test_qr.py` | 27-check validation battery |

## Limitations

- Versions 1–10 only (covers the vast majority of real-world codes).
- Detector assumes a roughly upright code (multiples of 90° fine, ~±15° tolerated).
- No ECI/kanji *encoding* (decoding handles them); structured-append skipped gracefully.
