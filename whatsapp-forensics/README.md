# WhatsApp Backup Forensics (Skill 17)

Hand-built WhatsApp backup forensics toolkit. Decrypts `msgstore.db.crypt14` (and crypt12) backups with a from-scratch AES-256-GCM + protobuf stack, then triages the decrypted `msgstore.db`: per-chat summaries, message composition, edits/reactions, call logs, anomaly flags — and carves **deleted messages out of SQLite b-tree freeblocks**.

## Dependencies

Stdlib only (`sqlite3`, `struct`, `hashlib`, `zlib`, …). One exception: `test_crypto.py` cross-checks the hand-rolled AES/GCM against **pycryptodome** as ground truth (`pip install pycryptodome`); the actual tools never need it.

## Run

Entry point: `wa_triage.py`.

```bash
cd whatsapp-forensics
python3 wa_triage.py <msgstore.db>          # triage a decrypted backup DB
python3 wa_triage.py fixture_msgstore.db    # demo on the fixture
python3 validate_all.py                     # end-to-end: build -> encrypt -> decrypt -> triage
python3 test_crypto.py                      # crypto cross-checks (needs pycryptodome)
```

`crypt_wa.py` also exposes `decrypt_crypt14(key_file, crypt14_file)` / `encrypt_crypt14(...)` for programmatic use; the 158-byte `key` file's bytes `[126:158]` are the AES key.

## Usage example

```bash
$ python3 wa_triage.py fixture_msgstore.db
# WhatsApp msgstore triage — fixture_msgstore.db
# tables/views: call_log, chat, chat_list, group_participants, jid, message, ...

## Chats
- chat 1 [1-1] Maya Chen: 43 msgs, 2025-09-20 11:23 -> 2025-10-08 03:40
- chat 2 [group] Tree Crew: 28 msgs, 2025-09-21 00:57 -> 2025-09-25 20:29
```

## Key learnings

- **Freeing a SQLite cell destroys the record's envelope, not its contents.** The first 4 bytes (payload-len + rowid varints) get overwritten by the freeblock header, but serial types and column data survive — the carver re-derives the serial list and fingerprints rows by content (the rowid is unrecoverable).
- **`PRAGMA secure_delete=ON` (Python's SQLite default) zeroes freed cells** — nothing to carve. Real WhatsApp must run with it off; always check the pragma first on a suspect DB.
- **crypt14 is not end-to-end encrypted — the device `key` file IS the secret.** The protobuf header only carries the nonce; bytes `[126:158]` of the 158-byte key file go straight into AES-256-GCM.
- **Edits/reactions never touch `message`** — they live in `message_add_on`, so the original wording of an "edited" message is always recoverable, and add-ons pointing at missing rows are a deletion signal.

## Files

- `wa_triage.py` — triage CLI (entry point): per-chat summaries, composition, edits/reactions, calls, anomalies, deleted-row carving, `timeline.csv`
- `crypt_wa.py` — key-file parsing, crypt12/crypt14 decrypt + fixture encryptors
- `crypto_aes256_gcm.py` — hand-rolled AES-256, GCM (GHASH), HKDF-SHA256
- `proto_min.py` — minimal protobuf wire-format codec (varints, fixed32/64, length-delimited, nested)
- `make_msgstore.py` — synthetic msgstore.db fixture builder (79 live rows, 8 deleted in freeblocks)
- `validate_all.py` — end-to-end validation script
- `test_crypto.py` — crypto checks vs pycryptodome oracle
- `fixture_msgstore.db` — synthetic fixture DB
- `e2e_key`, `e2e_msgstore.db.crypt14`, `e2e_msgstore.db`, `e2e_decrypted.db` — small end-to-end encrypt/decrypt fixtures
