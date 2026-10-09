# Browser Extension CRX Forensics (Skill 18)

Hand-rolled, zero-dependency toolkit for dissecting Chrome extensions. Parses the CRX3 package format (protobuf codec written from scratch), verifies the extension ID cryptographically, unpacks the embedded ZIP with a hand-written ZIP reader, and triages the extension with a static-analysis engine: manifest permission risk model (~30 permissions), host-pattern and content-script flags, and a ~30-pattern JS sink scanner (cookie theft, keylogging, `webRequest` interception, `eval`, exfil URLs).

## Dependencies

Stdlib only (`struct`, `zlib`, `json`, `hashlib`, …). No pip packages.

## Run

Entry point: `crxray.py`.

```bash
cd browser-extension-forensics
python3 crxray.py fixtures/benign.crx     # parse + triage a .crx file
python3 crxray.py fixtures/evil.crx       # malicious fixture -> MALICIOUS (100/100)
python3 crxray.py <unpacked-dir>          # triage an unpacked extension directory
python3 crxray.py ~/.../Preferences       # enumerate installed extensions, flag sideloads
python3 build_fixtures.py                 # regenerate the fixture .crx files
```

## Usage example

```bash
$ python3 crxray.py fixtures/evil.crx
CRX3: id=haebfhaicgknbkifcgpdnbklclcmegke crx_id_match=True zip_offset=332 keys=1
=== fixtures/evil.crx ===
verdict: MALICIOUS  (score 100/100)
  [+40] permission "<all_urls>": full host access
  [+35] exfil: cookie read + remote POST in content.js
```

## Key learnings

- **Naive static scoring convicts the innocent.** uBlock Origin's element-picker tripped the keylogger pattern and its cookie rules tripped `document.cookie`. The fix is a taint-lite rule: sinks keep full weight only when the *same file* also exfiltrates (fetch/XHR/sendBeacon to a remote URL).
- **Data theft needs a destination.** Zero exfil sinks anywhere means the verdict can never be MALICIOUS, no matter how broad the permissions. Permissions say what it *may* do; sinks say what it *does*; exfil destinations are what convict.
- **`crx_id = SHA256(public_key_DER)[:16]`**, and the 32-char Web Store id is each nibble mapped onto `a`–`p` — verified against the embedded value on parse.
- A non-Web-Store `update_url`, sideload flags in the `Preferences` artifact, and remote-code CSP are the classic "installed outside the store" tells.

## Files

- `crxray.py` — entry point: CRX3 parser (magic/version/header framing, hand protobuf codec), ZIP reader, manifest analyzer, JS sink scanner, CLEAN/SUSPICIOUS/MALICIOUS triage engine
- `build_fixtures.py` — builds the fixture CRX3s byte-correct
- `fixtures/benign.crx` — clean fixture (verdict CLEAN, 2/100)
- `fixtures/evil.crx` — cookie-stealer + keylogger + webRequest + `<all_urls>` + custom update_url (verdict MALICIOUS, 100/100)
- `testkey.pem`, `testkey_pub.der` — RSA test signing key (private + public DER)
