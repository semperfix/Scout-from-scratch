# Audio Forensics

Splice detection using electrical-hum (ENF) continuity analysis, plus
optional local speech transcription. Mains-powered recordings carry a faint
50/60 Hz hum whose phase is continuous in an unedited take; a cut, insert,
or join from another take almost always breaks that continuity. The triage
CLI tracks the hum with a hand-written Goertzel detector and flags phase /
amplitude breaks as splice candidates, with RMS-energy jumps and
zero-crossing-rate shifts as supporting signals. Limitation: hum-free
recordings and same-recording rearrangements may not be detectable.
All DSP is hand-written -- `math`, `struct`, `wave` only.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** for all analysis.
- **Optional:** `vosk` (`pip install vosk`) plus a model, only if you want
  the `--transcribe` path. Nothing else needs it.

## How to run

**Analyze a WAV for edits** (entry point `audiocheck.py`):

```bash
python3 audiocheck.py rec.wav
python3 audiocheck.py rec.wav --freq 50      # force 50 Hz (default: auto)
python3 audiocheck.py rec.wav --transcribe --model /path/to/model
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `WORTH-A-LOOK` / `SPLICE-LIKELY`).

**Build the test fixtures** (synthesized with `struct`/`math` only):

```bash
python3 mkfixtures.py   # writes ./fixtures/
```

**Use the analysis as a library:**

```python
from enf import read_wav, select_hum_freq, enf_discontinuities

wav = read_wav("rec.wav")
freq, track = select_hum_freq(wav["mono"], wav["sr"])
for t, kind, detail in enf_discontinuities(track):
    print(f"splice candidate at {t:.2f}s: {kind} -- {detail}")
```

## Example

```bash
$ python3 audiocheck.py fixtures/clean.wav
file: fixtures/clean.wav  (44100 Hz, 1 ch, 16-bit, 4.00 s)
ENF: tracking 60 Hz hum over 40 windows (median SNR 40.4 dB)
VERDICT: CLEAN (hum continuous, no edit signatures)

$ python3 audiocheck.py fixtures/spliced.wav
file: fixtures/spliced.wav  (44100 Hz, 1 ch, 16-bit, 4.00 s)
ENF: tracking 60 Hz hum over 40 windows (median SNR 38.3 dB)
  [!] t=  2.00s  ENF phase discontinuity: residual 1.59 rad (baseline 0.00)
  [.] t=  2.00s  ZCR shift (supporting): ZCR 0.41x
VERDICT: SPLICE-LIKELY -- ENF discontinuity at 2.00s; supporting: 0 energy, 4 ZCR
```

(The fixture's second take shifts the hum clock by 4.2 ms = 1.58 rad at
t=2.0 s; the detector reports 1.59 rad -- the injected value, recovered.)

## Key learnings

- **Phase continuity is the signal; the cross-product is the trick.** For a
  continuous hum the window-to-window cross product `z[k]*conj(z[k-1])` has
  constant phase, so a splice shows up as a residual spike against the
  *median* baseline -- robust to a few edits, no absolute-phase bookkeeping.
- **The 0.1 s window is not arbitrary.** At 44.1/48 kHz it holds an integer
  number of hum cycles (6 at 60 Hz, 5 at 50 Hz), so the Goertzel bin is
  exact and a continuous hum has ~zero cross-product phase by construction.
- **SNR must be measured at the window's sidelobe nulls.** The first attempt
  used +/-5 Hz bins and reported 3.8 dB on a clean tone -- the "noise" was
  the hum's own rectangular-window sidelobes (0.637 of main-lobe at half-bin
  offset). Bins at +/-10/+/-20 Hz sit at exact sidelobe nulls for a stable
  hum; same fixture then reads 40 dB.
- **Fixture hygiene matters as much as detector code.** The speech bed needed
  fundamentals clear of 50-70 Hz and a vibrato completing exactly one cycle
  per window (periodic in-window, zero DFT leakage) before the hum phase was
  measurable at all.

## Files

| File | What it does |
|---|---|
| `audiocheck.py` | **Entry point**: WAV triage CLI -- ENF track, splice candidates, verdict; optional `--transcribe` via vosk |
| `enf.py` | Hand-written Goertzel, hum auto-select (50/60), phase/amplitude continuity, RMS-energy and ZCR supporting signals |
| `mkfixtures.py` | Synthesizes `clean.wav` (continuous hum) and `spliced.wav` (phase-jumped second take at t=2.0 s) |
| `fixtures/` | Generated test audio (regenerate with `mkfixtures.py`) |

## Limitations

- Needs a measurable mains hum. Battery-powered / outdoor / heavily
  denoised recordings may have none -- the SNR readout tells you when the
  analysis is untrustworthy (below ~3 dB the detector stays silent).
- Same-recording rearrangements (cutting within one continuous take) keep hum
  phase continuous and are invisible to ENF; energy/ZCR may still catch them.
- A sophisticated forger can re-synthesize continuous hum across a splice.
  ENF is evidence, not proof.
- Transcription is a thin wrapper around vosk, not a built-from-scratch
  recognizer; accuracy depends entirely on the model you point it at.
- Only WAV/PCM input (stdlib `wave`); MP3/AAC would need a decoder.
