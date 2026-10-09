#!/usr/bin/env python3
"""audiocheck: audio splice detection via ENF (mains-hum) continuity.

Reads a WAV file (stdlib `wave`), tracks the 50/60 Hz electrical hum with a
hand-written Goertzel detector, and flags phase/amplitude discontinuities
as splice candidates. RMS-energy jumps and zero-crossing-rate shifts are
reported as supporting signals.

Speech transcription is OPTIONAL: it needs `vosk` plus a model
(`pip install vosk`), which is not required for any of the analysis below.
Pass --transcribe --model <path> to attempt it when available.

Usage: python3 audiocheck.py rec.wav [--freq 60] [--transcribe --model m.zip]
Exit 0 always; the VERDICT line is the machine-readable result
(CLEAN / SPLICE-LIKELY).
"""
import argparse
import math
import sys

from enf import (read_wav, select_hum_freq, hum_track, enf_discontinuities,
                 frame_stats, energy_jumps, zcr_shifts)


def transcribe(path, model_path):
    """Best-effort local transcription via vosk. Returns text or a note."""
    try:
        import vosk  # optional dependency
    except ImportError:
        return ("transcription skipped: vosk not installed "
                "(pip install vosk, plus a model from alphacephei.com)")
    import wave as _wave
    import json
    try:
        model = vosk.Model(model_path)
    except Exception as e:
        return f"transcription skipped: could not load model: {e}"
    rec = vosk.KaldiRecognizer(model, 16000)
    words = []
    with _wave.open(path, "rb") as w:
        # vosk wants 16 kHz mono 16-bit; resample note if mismatched
        while True:
            data = w.readframes(4000)
            if not data:
                break
            if rec.AcceptWaveform(data):
                words.append(json.loads(rec.Result()).get("text", ""))
    words.append(json.loads(rec.FinalResult()).get("text", ""))
    return " ".join(w for w in words if w).strip() or "(no speech recognized)"


def main():
    ap = argparse.ArgumentParser(
        description="Splice detection in WAV files via mains-hum (ENF) "
                    "continuity analysis.")
    ap.add_argument("wav", help="WAV file to analyze")
    ap.add_argument("--freq", type=float, choices=(50.0, 60.0), default=None,
                    help="force hum frequency (default: auto-select 50/60)")
    ap.add_argument("--transcribe", action="store_true",
                    help="attempt local transcription (needs vosk + --model)")
    ap.add_argument("--model", default=None,
                    help="path to vosk model directory/zip")
    args = ap.parse_args()

    try:
        wav = read_wav(args.wav)
    except Exception as e:
        sys.exit(f"cannot read {args.wav}: {e}")
    mono, sr = wav["mono"], wav["sr"]
    print(f"file: {args.wav}  ({sr} Hz, {wav['channels']} ch, "
          f"{wav['width'] * 8}-bit, {wav['duration']:.2f} s)")

    if args.freq:
        freq, track = args.freq, hum_track(mono, sr, args.freq)
    else:
        freq, track = select_hum_freq(mono, sr)
    med_snr = sorted(s for _, _, s in track)[len(track) // 2]
    print(f"ENF: tracking {freq:.0f} Hz hum over {len(track)} windows "
          f"(median SNR {med_snr:.1f} dB)")

    enf_events = enf_discontinuities(track)
    stats = frame_stats(mono, sr)
    ej = energy_jumps(stats)
    zc = zcr_shifts(stats)

    for t, kind, detail in enf_events:
        print(f"  [!] t={t:6.2f}s  ENF {kind} discontinuity: {detail}")
    for t, kind, detail in ej:
        print(f"  [.] t={t:6.2f}s  energy jump (supporting): {detail}")
    for t, kind, detail in zc:
        print(f"  [.] t={t:6.2f}s  ZCR shift (supporting): {detail}")

    if args.transcribe:
        if not args.model:
            print("transcription skipped: --model <path> required")
        else:
            print("transcript: " + transcribe(args.wav, args.model))

    strong = [e for e in enf_events if e[1] in ("phase", "amplitude")]
    if strong:
        locs = ", ".join(f"{t:.2f}s" for t, _, _ in strong)
        extra = f"; supporting: {len(ej)} energy, {len(zc)} ZCR" if (ej or zc) else ""
        print(f"VERDICT: SPLICE-LIKELY -- ENF discontinuity at {locs}{extra}")
    elif ej:
        print(f"VERDICT: WORTH-A-LOOK -- energy jumps at "
              + ", ".join(f"{t:.2f}s" for t, _, _ in ej)
              + " but hum phase continuous")
    else:
        print("VERDICT: CLEAN (hum continuous, no edit signatures)")


if __name__ == "__main__":
    main()
