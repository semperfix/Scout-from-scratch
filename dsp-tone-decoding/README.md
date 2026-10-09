# DSP & Telephony Tone Decoding — FFT, DTMF, and Morse from Scratch

A from-scratch digital-signal-processing toolkit for telephony-tone forensics:
`dsp.py` (~430 lines) implements an iterative radix-2 Cooley-Tukey FFT + IFFT
(conjugation trick), one-sided amplitude spectrum, parabolic-interpolated peak
frequency estimation, a Goertzel single-frequency detector, Hann-windowed
spectrogram, full DTMF encode/decode (all 16 keys), Morse encode/decode via
tone envelope, and a hand-rolled 16-bit PCM WAV codec (struct-based
chunk-walking). `tonedec.py` is the CLI: `gen-dtmf` / `decode-dtmf` /
`gen-morse` / `decode-morse` / `tones`. `test_dsp.py`: **31/31 pass**, and the
stress tests measured the honest operating envelope: DTMF decodes 5/5 even at
**0 dB SNR** with 1% frequency jitter, while envelope-based Morse holds 5/5 to
12 dB, 4/5 at 8 dB, and 0/5 at 5 dB.

## Dependencies

- **numpy** (the one non-stdlib dependency; `dsp.py` leans on it for
  vectorized math). Everything else is stdlib.
- `pip install numpy` if it isn't already present. It is not vendored here.

## How to run

```
python3 test_dsp.py                     # 31/31 unit + stress checks

python3 tonedec.py gen-dtmf "9125550134" dial.wav --snr 12
python3 tonedec.py decode-dtmf dial.wav        # -> 9125550134

python3 tonedec.py gen-morse "HELLO WORLD" morse.wav --wpm 20 --snr 12
python3 tonedec.py decode-morse morse.wav --wpm 20

python3 tonedec.py tones dial.wav -n 8         # strongest frequency components
```

## Usage example

```python
import sys
sys.path.insert(0, ".")
from dsp import dtmf_encode, dtmf_decode, wav_write, wav_read

# synthesize keypad tones at 12 dB SNR, write to a WAV, decode them back
x = dtmf_encode("9125550134", snr_db=12)
wav_write("/tmp/dial.wav", x)
audio, fs = wav_read("/tmp/dial.wav")
print(dtmf_decode(audio, fs))   # -> 9125550134
```

## Limitations

- **Requires numpy.** This is the only skill in the series so far that isn't
  stdlib-only; `pip install numpy` is needed before anything runs.
- **Morse decode dies in heavy noise.** Measured: 0/5 at 5 dB SNR. Once the
  noise floor ≈ the signal level, envelope timing is gone — that's physics,
  not a tunable.
- **Parabolic peak interpolation has ~0.1-bin systematic bias on a Hann
  window** (pinned by test at 444.7 Hz). Quinn's estimator would do better;
  the honest threshold used is 0.2 Hz.
- **Goertzel window length is a jitter-vs-resolution tradeoff:** 25 ms windows
  (40 Hz bins) tolerate ±1.5% line jitter; longer windows would sharpen
  resolution but mis-handle jittered tones.
- **DTMF decode is tuned for 8 kHz telephony audio** (row/column frequencies
  697–1633 Hz, 40 ms minimum digit timing); it won't decode faster-than-spec
  bursts or non-telephony tone plans.
- Only 16-bit PCM WAV files are read/written; no MP3/OGG/compressed formats.
