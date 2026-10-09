# Email Security Forensics

SPF, DKIM, and DMARC learned hands-on: an SPF record parser/evaluator
(RFC 7208), a complete DKIM signer and verifier built from scratch
(relaxed/simple canonicalization, body hash, RSA-SHA256 with real
PKCS#1 v1.5 padding, hand-rolled RSA and DER), and a DMARC parser with
identifier-alignment checks (RFC 7489). The `emailauth.py` CLI takes a raw
email file plus a stub-DNS JSON file and reports DKIM/SPF/DMARC verdicts —
fully offline.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — no third-party packages, no crypto libraries

## How to run

Entry point is `emailauth.py` (argparse):

```bash
# build fixtures: signed.eml, tampered.eml, unsigned.eml, dns-stub.json
python3 make_fixtures.py

# verify a message (offline; DNS comes from the stub file)
python3 emailauth.py fixtures/signed.eml --dns-stub fixtures/dns-stub.json \
    --mailfrom alice@example.com

# same message from an IP outside the SPF range -> SPF FAIL
python3 emailauth.py fixtures/signed.eml --dns-stub fixtures/dns-stub.json \
    --mailfrom alice@example.com --ip 203.0.113.9

# tampered body -> DKIM bh MISMATCH
python3 emailauth.py fixtures/tampered.eml --dns-stub fixtures/dns-stub.json \
    --mailfrom alice@example.com

# module self-tests
python3 spf.py && python3 dkim.py && python3 dmarc.py
```

Library use:

```python
from dkim import generate_rsa_key, dkim_dns_txt, sign_raw_email, verify_raw_email

n, e, d = generate_rsa_key(bits=1024)
signed = sign_raw_email(open("msg.eml","rb").read(), "example.com", "sel1", (n, e, d))
dns = {"sel1._domainkey.example.com": dkim_dns_txt(n, e)}
print(verify_raw_email(signed, dns.get))   # [{'status': 'pass', ...}]

from spf import evaluate_spf
evaluate_spf("v=spf1 ip4:192.0.2.0/24 -all", "192.0.2.44", "example.com", dns_stub)
```

Exit codes for `emailauth.py`: 0 = DMARC pass/none, 1 = DMARC fail, 2 = usage error.

## Example

```bash
$ python3 emailauth.py fixtures/signed.eml --dns-stub fixtures/dns-stub.json --mailfrom alice@example.com
From domain: example.com

DKIM:
  d=example.com s=sel1 a=rsa-sha256: PASS -- body hash and RSA signature valid (bh_match=True, sig_valid=True)
SPF: PASS (ip=192.0.2.44, mailfrom=alice@example.com, domain=example.com) -- matched +ip4:192.0.2.0/24
DMARC: PASS (policy p=reject, disposition=none) -- aligned auth: dkim=True spf=True

$ python3 emailauth.py fixtures/tampered.eml --dns-stub fixtures/dns-stub.json --mailfrom alice@example.com
DKIM:
  d=example.com s=sel1 a=rsa-sha256: FAIL -- signature valid but bh MISMATCH -- body was modified after signing (bh_match=False, sig_valid=True)
SPF: PASS (ip=192.0.2.44, mailfrom=alice@example.com, domain=example.com) -- matched +ip4:192.0.2.0/24
DMARC: PASS (policy p=reject, disposition=none) -- aligned auth: dkim=False spf=True
```

## Key learnings

- **A tampered body does NOT invalidate the DKIM signature.** The RSA
  signature covers the headers *including the bh= tag*, not the body bytes.
  Change one word of the body and you get `sig_valid=True, bh_match=False` —
  exactly what the verifier above reports. The body hash is the tamper
  evidence; the signature is the authorship evidence. Two different jobs.
- **DKIM verification is byte-exact archaeology.** The verifier must
  reconstruct the *exact* canonicalized bytes the signer hashed: unfold the
  header, blank only the `b=` value (regex on the unfolded header, keeping
  every other byte), then relaxed-canonicalize. Re-serializing parsed tags
  would not reproduce the signer's bytes.
- **SPF authenticates the envelope, not the From: line.** `SPF: PASS` on the
  fixture says `alice@example.com`'s *sending IP* is authorized — a phisher
  with their own domain and valid SPF still passes SPF. DMARC's alignment
  check is what ties authentication to the domain the user sees.
- **DMARC `p=reject` with no aligned pass is the only combination that would
  have stopped the tampered mail at a strict receiver** — here the aligned
  SPF pass still carried it. Defense in depth is not redundancy; each
  mechanism covers the others' blind spots.
- **Keygen bug class, reused lesson:** the RSA key generator from the crypto
  skill regenerates primes until gcd(e, φ)=1 instead of bumping e, so the
  DKIM `e=65537` is always the real exponent.

## Files

| File | What it does |
|---|---|
| `emailauth.py` | **Entry point**: argparse CLI — DKIM/SPF/DMARC triage for a raw email + stub DNS |
| `dkim.py` | DKIM signer/verifier: relaxed/simple canonicalization, bh, PKCS#1 v1.5 RSA-SHA256 (hand-rolled RSA + DER), DNS TXT publish/parse |
| `spf.py` | SPF parser + evaluator: qualifiers, ip4/ip6/a/mx/include/redirect/all, CIDR matching, 12-case self-test |
| `dmarc.py` | DMARC parser + relaxed/strict alignment, policy disposition, 7-case self-test |
| `make_fixtures.py` | Generates `fixtures/`: signed, tampered, and unsigned emails + stub DNS JSON |
| `fixtures/` | `signed.eml`, `tampered.eml`, `unsigned.eml`, `dns-stub.json` |

## Limitations

- **No live DNS.** Verification reads TXT/A/MX from `--dns-stub` JSON. Live
  resolution needs network; the dns-internals skill in this repo builds the
  resolver that could back this.
- Organizational-domain detection is last-two-labels, not the Public Suffix
  List (documented simplification in `dmarc.py`).
- Only `c=relaxed/simple` and `a=rsa-sha256` are implemented; `simple/simple`
  and `rsa-sha1` are not.
- `ptr` mechanism is treated as non-match (it is deprecated in RFC 7208).
- Line endings are normalized to CRLF before canonicalization; a signer that
  hashed bare-LF bodies would not verify (pragmatic real-world choice).
