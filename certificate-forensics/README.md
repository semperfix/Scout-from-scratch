# X.509 / PKI Certificate Forensics (from scratch)

Read any TLS certificate the way a forensic analyst does: parse it byte-by-byte
from DER, verify its signature with hand-rolled RSA/ECDSA/Ed25519, walk its chain
to a trust anchor, check the hostname binding, and triage it for the tells of
phishing, interception, and misconfiguration. Plus Certificate Transparency OSINT
— passive subdomain enumeration from public CT logs without sending the target a
single packet.

**Zero dependencies — stdlib only.** (The TLS fetch in `certcheck.py` shells out
to the system `openssl` binary for the socket layer; the from-scratch work is
parse + verify, not the handshake.)

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no pip packages required.
- `openssl` CLI on PATH (optional; only needed for `certcheck.py host:port`
  live-fetch mode).

## How to run

**Triage a certificate** (entry point `certcheck.py`):

```bash
python3 certcheck.py host[:port]          # live TLS fetch (read-only)
python3 certcheck.py --pem file.crt [--host example.com]
python3 certcheck.py --ct example.com    # CT-log subdomain enumeration (via crt.sh)
```

Prints parsed certs, per-link chain notes, ranked findings, and a verdict.

**Run the validation battery:**

```bash
python3 test_cert.py    # 68 checks: DER edge cases, openssl cross-validation, chain building
```

## Example

```bash
$ python3 certcheck.py --pem pki/leaf.crt
  subject : CN=example.com
  issuer  : CN=Test EC Root
  serial  : 70b895cb766297e14c2176e72adbebede78d7b9
  sig alg : ecdsa-with-SHA256
  key     : ecPublicKey 256-bit (secp256r1)
  validity: 2026-10-09 00:45:51Z .. 2029-01-11 00:45:51Z
  SANs    : example.com, www.example.com

chain: UNKNOWN_ISSUER -- no issuer found for CN=Test EC Root

[CRIT] CHAIN_UNKNOWN_ISSUER: chain validation: UNKNOWN_ISSUER

verdict: SUSPICIOUS
```

Triage flags: `WEAK_SIG_ALG`, `SHORT_RSA_KEY`, `EXPIRED`, `LONG_LIVED` (>825d),
`SELF_SIGNED`, `HOSTNAME_MISMATCH`, `PUNYCODE_SAN`, `LOW_ENTROPY_SERIAL`,
`MISSING_AKI/SKI`, `MANY_SANS`, plus chain-status folding.

## Key learnings

- **Never trust memorized constants — verify curve parameters against an oracle.**
  Hand-typed P-256 group order was wrong in the last 10 hex digits; P-384's `b`
  and `Gx` were garbled. All parameters are now generated from
  `openssl ecparam -param_enc explicit` output, and the battery re-verifies them.
- **Self-referential tests lie.** `P256.mul(P256.n) is None` passed with the
  *wrong* n — because `mul` reduces `k %= n` first, so `n % n == 0` always returns
  the identity. The test was vacuous; fixed by checking against the openssl order.
- **Synthetic fixtures only cover what you thought of; a corpus sweep covers what
  exists.** All fixtures used sha256, so a wrong sha384 DigestInfo length passed
  the battery — but a sweep over 121 real system roots caught 18 failures
  (Amazon Root CA 2, GTS R1, DigiCert G4/G5…).
- **Absurd validity windows are interception tells.** A live fetch returned a leaf
  issued by a sandbox egress CA with validity 1975 → 4096 (774,680 days) — no
  public CA mints 2,121-year certs. The triage engine flags it `LONG_LIVED`.

## Files

| File | What it does |
|---|---|
| `certcheck.py` | **Entry point**: triage CLI — `host[:port]`, `--pem`, `--ct` modes |
| `der.py` | DER TLV parser: tags/lengths, OID encode/decode, INTEGER, BIT STRING, UTCTime/GeneralizedTime, PEM handling, `openssl asn1parse`-style pretty printer |
| `x509.py` | RFC 5280 certificate parser: DNs, validity, SubjectPublicKeyInfo (RSA/EC/Ed25519), extensions (SKI, AKI, KeyUsage, SAN, BasicConstraints, EKU, CRLDP, AIA, policies). Slices exact `tbsCertificate` bytes for verification |
| `ecc.py` | ECDSA over NIST P-256/P-384/P-521 + Ed25519 (RFC 8032) sign/verify |
| `verify.py` | RSA PKCS#1 v1.5 verification (DigestInfo table), ECDSA/Ed25519 dispatch, chain builder (issuer-DN + AKI/SKI binding, `CA:TRUE`/`keyCertSign` enforcement), RFC 6125-lite hostname verification, triage engine |
| `ctlog.py` | crt.sh CT-log client: subdomain enumeration + infra-name heuristics (`vpn`, `staging`, `owa`, `jenkins`, …) |
| `test_cert.py` | 68-check validation battery |
| `pki/` | Test PKI (openssl-generated fixtures): RSA root/leaf, EC P-256 & P-384 roots/leaves, 3-level root→intermediate→leaf, non-CA "intermediate" (negative), 10-year leaf, punycode-SAN leaf, sha1/1024-bit weak leaf |

## Stated limitations

- No RSA-PSS or DSA signature verification (rare; reported as unsupported, not
  silently accepted). No revocation checking (OCSP/CRL URLs are extracted and
  displayed only). NameConstraints parsed minimally, not enforced.
