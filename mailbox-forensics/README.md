# Email Mailbox mbox/Maildir Forensics (Skill 21)

Container-level email forensics: what's *around* the message, not just inside it. Hand-rolled parser (~330 lines, zero deps) for mbox and Maildir with a triage engine covering timestamp spoofing, risky attachments, UID-gap deletion evidence, and tamper/corruption tells. Complements message-level checks (SPF/DKIM/DMARC) by answering "what does this mailbox actually contain, what's missing, and what's lying."

## Dependencies

Stdlib only (`re`, `base64`, … — no `email` module needed; headers parsed by hand). No pip packages. Tests cross-validate against stdlib `mailbox` as an independent oracle.

## Run

Entry point: `mbtriage.py`.

```bash
cd mailbox-forensics
python3 mbtriage.py fixtures/inbox.mbox            # timeline + threads + findings
python3 mbtriage.py fixtures/inbox.mbox timeline.csv  # also export CSV timeline
python3 mbtriage.py fixtures/maildir              # triage a Maildir directory
python3 mbox_gen.py                               # regenerate the fixtures (deterministic)
python3 test_mbox.py                              # 28 checks
```

## Usage example

```bash
$ python3 mbtriage.py fixtures/inbox.mbox
== 8 messages ==

-- timeline --
2026-10-06T15:42:11-04:00 | thinking about you | Stephanie Burnside <stephanie.burnside@example.com> |
...

-- findings --
spoofed date: M4 Date=2024-10-14 vs Received=2026-10-07 (skew flag)
```

## Key learnings

- **mbox has no index — the `From_` line is data, not metadata.** A forged or unescaped `From ` body line silently re-partitions the mailbox; every real reader splits on it. Detection: check whether the "new message" that follows has headers.
- **The spoofed-`Date:` tell is structural, not textual.** Sort the timeline by the header and the liar sticks out; compare against `Received:` (written by servers, harder to fake) for the real number.
- **Deletion evidence survives deletion.** In Maildir the file is gone, but a UIDL log still shows the gap — same pattern as Skill 17's SQLite freeblocks and Skill 20's registry cells: forensic recovery is always about the *allocator's* bookkeeping, not the data.
- **`tmp/` files are delivery-in-progress by design.** A file parked there is either a crash mid-delivery or something deliberately staged — either way, not a normal message.

## Files

- `mbtriage.py` — entry point CLI: timeline + threads + findings, CSV export
- `mboxparse.py` — hand-rolled parser: mbox reader, Maildir reader, RFC 5322 headers (unfolding, RFC 2047 encoded-words, RFC 2822 dates), MIME walker (base64/QP, attachment SHA-256), threading, triage
- `mbox_gen.py` — deterministic fixture generator (8-msg mbox incl. corrupt + spoofed-date cases, Maildir with UID gap and torn `tmp/` file)
- `test_mbox.py` — 28 checks, incl. cross-validation vs stdlib `mailbox`
- `fixtures/inbox.mbox`, `fixtures/corrupt.mbox`, `fixtures/ground_truth.txt`, `fixtures/maildir/` (cur/new/tmp + uidl.txt)
