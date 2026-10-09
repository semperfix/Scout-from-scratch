# Image Forensics

Hand-built EXIF/JPEG/WebP parsers, encoding fingerprinting, and an honest,
encoder-free take on error-level analysis (ELA) for tamper detection.
Inspects camera/timestamp/GPS metadata, detects likely pasted regions, and
identifies explicit AI-generation metadata. Limitation: modern AI images don't
reliably expose classic GAN artifacts -- and stdlib Python has no JPEG
encoder, so true re-encode ELA is replaced by two encoder-free proxies
(DQT fingerprinting + 8x8 block-grid analysis). No PIL, no piexif, no numpy.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** -- `struct`, `hashlib`, `random`, `argparse`, `wave`-free.

## How to run

**Triage a suspicious image** (entry point `imgcheck.py` -- auto-detects
JPEG / WebP / BMP by magic bytes):

```bash
python3 imgcheck.py suspect.jpg
python3 imgcheck.py suspect.webp
python3 imgcheck.py suspect.bmp
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `WORTH-A-LOOK` / `TAMPER-SUSPECT`).

**Build the test fixtures** (hand-crafted byte-by-byte, no encoders):

```bash
python3 mkfixtures.py   # writes ./fixtures/
```

**Use the parsers as a library:**

```python
from jpegparse import parse_jpeg, KNOWN_DQT, gps_decimal

j = parse_jpeg(open("cam.jpg", "rb").read())
print(j["sof"])                       # {'width': 640, 'height': 480, ...}
print(j["exif"]["ifd0"]["Make"])       # 'Canon'
print(gps_decimal(j["exif"]["gps"]))   # (33.75, -84.3833...)
for t in j["dqt"]:
    print(t["id"], KNOWN_DQT.get(t["md5"], "CUSTOM"))

from webpparse import parse_webp, xmp_flags
w = parse_webp(open("ai.webp", "rb").read())
print(xmp_flags(w["xmp"]))             # {'ai': ['trainedAlgorithmicMedia', ...], ...}
```

## Example

```bash
$ python3 imgcheck.py fixtures/cam.jpg
file: fixtures/cam.jpg  (JPEG, 640x480, 1ch, SOF0)
markers: APP0 APP1 DQT SOF0 DHT SOS EOI
EXIF (little-endian TIFF):
  Make: Canon
  Model: Canon EOS 5D Mark IV
  DateTime: 2024:05:01 12:00:00
  GPS: 33.750000, -84.383333
quantization tables:
  table 0: IJG standard luminance  md5=5abb297f9f0c8d89...
  table 1: IJG standard chrominance  md5=397176041475709b...
VERDICT: CLEAN (GPS coordinates present (location privacy))

$ python3 imgcheck.py fixtures/ai.webp
file: fixtures/ai.webp  (WebP, 512x512)
chunks: VP8X(10) VP8 (18) XMP (398) EXIF(52)
VP8X: canvas 512x512, alpha=False anim=False iccp=False exif-chunk=True xmp-chunk=True
EXIF chunk:
  Make: OpenAI
  Software: DALL-E
XMP: present (398 chars)
VERDICT: TAMPER-SUSPECT -- AI-generator software tag: 'DALL-E'; XMP AI-generation markers: trainedAlgorithmicMedia, DALL
```

## Key learnings

- **Quantization tables are an encoding fingerprint.** Two photos from the same
  camera model share identical DQT md5s; a re-saved or composited image almost
  never does. Comparing table fingerprints against the known IJG standard pair
  catches pipeline changes without decoding a single pixel.
- **JPEG DQT segments store coefficients in zig-zag order, not row-major.**
  The first draft compared raw bytes against the spec's natural-order tables
  and every table read "custom". The fix is an explicit inverse zig-zag map --
  a one-line conceptual error that flipped every verdict.
- **TIFF offsets are relative to the TIFF header, not the file.** APP1 EXIF
  starts with `Exif\0\0`; the IFD value-offsets that follow are relative to
  the byte after that 6-byte header. A second classic trap: the GPS IFD
  pointer's offset must be computed *after* the IFD0 entry for it exists, or
  it points into the middle of IFD0.
- **True ELA needs an encoder; the block grid is the encoder-free tell.**
  JPEG works in 8x8 blocks, so a pasted region with a different compression
  history shows anomalous 8x8 block-boundary discontinuity. The fixture proves
  it: the synthetic pasted region (blocks 5..8,5..8) lights up as a clean box
  outline in the ASCII map, with edge/interior scores orders of magnitude
  above the median.

## Files

| File | What it does |
|---|---|
| `imgcheck.py` | **Entry point**: triage CLI -- EXIF/DQT (JPEG), XMP AI-metadata (WebP), block-grid (BMP) + verdict |
| `jpegparse.py` | Hand-rolled JPEG marker walk, DQT extraction, EXIF/TIFF parser (both endiannesses, IFD0/EXIF/GPS IFDs), IJG standard-table fingerprints |
| `webpparse.py` | Hand-rolled RIFF/WebP parser: VP8/VP8L/VP8X headers, XMP extraction + AI/editor marker scan, EXIF chunk reuse of the TIFF parser |
| `blockgrid.py` | 24-bit BMP reader + per-8x8-block edge/interior gradient analysis and anomaly map |
| `mkfixtures.py` | Byte-by-byte fixture builder: `cam.jpg`, `edited.jpg`, `ai.webp`, `ela.bmp` |
| `fixtures/` | Generated test images (regenerate with `mkfixtures.py`) |

## Limitations

- **No true ELA.** Re-encoding at a known JPEG quality requires a JPEG
  *encoder*; the stdlib has none. Shipped instead: DQT fingerprint comparison
  (pipeline-change detection on JPEG) and 8x8 block-grid discontinuity
  analysis (on BMP). Both are strictly weaker than real ELA.
- EXIF parsing covers IFD0/EXIF/GPS IFDs and the common tag set; makernote
  blobs are not decoded.
- WebP covers still-image VP8/VP8L/VP8X; animated (ANIM/ANMF) frames are
  listed, not decoded.
- Verdicts are triage heuristics, not proof: a `CLEAN` means "no signal
  fired", not "authentic".
