# Bitcoin Transaction Forensics (Skill 22)

A complete hand-rolled Bitcoin stack (zero dependencies) validated against live mainnet data: SHA-256 and RIPEMD-160 from scratch, Base58Check, Bech32/Bech32m, secp256k1 arithmetic, legacy + segwit transaction parse/serialize, script disassembly and classification, merkle roots, sighash builders, and full signature verification. The `trace.py` triage CLI decodes any transaction and reports structure, value flow, fees, and scam-relevant heuristics (change detection, dust, OP_RETURN labels, RBF, multisig policy).

## Dependencies

Stdlib only. No pip packages. `tests/validate_live.py` fetches live data from blockstream.info via stdlib `urllib` (needs network).

## Run

Entry point: `trace.py`.

```bash
cd bitcoin-forensics
python3 trace.py --help
python3 trace.py <txid> --fetch      # pull raw tx (+ prevouts) from blockstream, dissect it
python3 trace.py --hex <rawhex>      # analyze offline from raw transaction hex
python3 tests/test_core.py           # 44 offline checks
python3 tests/validate_live.py       # live mainnet validation (needs network)
```

## Usage example

```bash
$ python3 trace.py 4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b --fetch
txid 4a5e1e4b...  1 in / 2 out   fee 226 sat (1.0 sat/vB)
  in 0: P2PKH  1A1zP1... -> verified OK
  out 0: P2PKH 12c6DS...  49.999774 BTC   (change guess)
  out 1: P2PKH 1HLoD9...  0.00010000 BTC  (dust)
```

## Key learnings

- **Never trust memorized constants in consensus code.** The hand-rolled script classifier failed on a real P2PKH script — the missing piece was `OP_SHA1 = 0xa7`, a disabled opcode that shifts every later opcode by one. The real table came from Bitcoin Core's `script.h`, verified against the wire.
- **Signatures are the easy part; sighash construction is the work.** ECDSA verify is ~20 lines once the curve math exists; the real complexity is rebuilding the exact preimage (legacy per-input script substitution vs BIP-143's hashed substructures) and getting byte order right (txids display reversed, serialize in wire order).
- **A test vector caught my confusion, not a code bug.** `hash160` of the compressed generator point equals BIP-173's published example — confirming the whole SHA-256→RIPEMD-160→bech32 chain independently. My "expected" addresses were misremembered (compressed/uncompressed swapped); the code was right.
- **Forensic shape > raw values.** A 1-in/10-out tx with a 2-of-3 multisig input reads as "service payout batch" before you look at a single amount — change detection, dust, and OP_RETURN labels turn a hex blob into a story.

## Files

- `trace.py` — entry point: forensic triage CLI (structure, per-input/output decode, address recovery, value flow, fee, signature validity, heuristics)
- `btc_core.py` — SHA-256, RIPEMD-160, HASH160/HASH256, Base58Check, Bech32/Bech32m, secp256k1 field/group arithmetic, ECDSA verify
- `btc_tx.py` — compactsize varints, script parser/disassembler (real opcode table), scriptPubKey classifier, legacy + segwit parse/serialize, txid/wtxid, block + merkle parse, sighash builders, DER signature parsing, P2PKH/P2WPKH verification
- `tests/test_core.py` — 44 offline checks
- `tests/validate_live.py` — live mainnet validation via blockstream.info
