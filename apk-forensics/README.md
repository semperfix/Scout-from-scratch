# Android APK Forensics From Scratch

Hand-rolled parsers for the full APK stack with zero Android tooling: the ZIP
container, binary `AndroidManifest.xml` (aapt2 wire format), and Dalvik DEX.
Produces a triage verdict — permissions vs. claimed function, exported
component attack surface, hardcoded servers/IPs, dynamic code loading,
suspicious APIs. Dissect any suspicious APK and tell whether it does what it
claims.

## Dependencies

- **Python 3** (3.10+ recommended)
- **stdlib only** — `zlib` (raw inflate for deflated ZIP entries), `hashlib`
  (DEX SHA-1), `re`, `struct`. (`build_fixture.py` uses stdlib `zipfile`, but
  only as a *writer* to create test fixtures; the parsers never touch it.)

## How to run

**Triage a suspicious APK** (entry point `apktriage.py`):

```bash
python3 apktriage.py suspect.apk
```

Exit 0 always; the `VERDICT:` line is the machine-readable result
(`CLEAN` / `WORTH-A-LOOK` / `SUSPICIOUS`).

**Use as a library:**

```python
import zipread, axml, dex

data = open("suspect.apk", "rb").read()
for e in zipread.list_entries(data):          # hand-rolled central directory
    print(e.name, e.method, e.uncomp_size)
manifest = axml.parse_axml(zipread.read_name(data, "AndroidManifest.xml"))
print(manifest["permissions"], manifest["components"])
d = dex.parse_dex(zipread.read_name(data, "classes.dex"))
print(d["strings"], d["methods"])             # strings + (class, method) refs
```

**Run the validation battery:**

```bash
python3 test_apk.py    # 20 checks: zipread byte-identical to stdlib zipfile,
                       # manifest/DEX assertions, tampered-DEX rejection,
                       # triage verdicts on both fixtures, CLI smoke
```

## Example

```bash
$ python3 apktriage.py fixtures/evil.apk
file: fixtures/evil.apk
package: com.evil.flashlight
zip entries: 4
  AndroidManifest.xml          method=deflated 1185 bytes
  classes.dex                  method=stored 508 bytes
  ...
dex: 12 strings, 4 method refs
signals:
  - dangerous permissions: android.permission.READ_SMS
  - exported attack surface: activity .MainActivity (intent-filter)
  - hardcoded URLs: http://evil.example.com/collect
  - hardcoded IPs: 45.155.204.9
  - suspicious API: SMS API (SmsManager) (string ref)
  - suspicious API: command execution (Runtime.exec)
  - suspicious API: crypto API (Cipher) (string ref)
  - suspicious API: dynamic code loading (DexClassLoader) (string ref)
VERDICT: SUSPICIOUS -- dangerous permissions: ...; exported attack surface: ...; ...

$ python3 apktriage.py fixtures/clean.apk
...
VERDICT: CLEAN
```

## Key learnings

- **The aapt2 binary-XML wire format really does use u32 fields where the old
  docs say u16.** String-pool indices, attribute ns/name indices and rawValue
  are all 32-bit; a parser built from the stale docs misaligns on the first
  attribute. UTF-8 string-pool entries also carry *two* length prefixes (char
  count, byte count), each in the 1-or-2-byte high-bit scheme.
- **Fixtures beat real APKs for parser validation.** The fixtures assemble
  binary AXML and DEX byte-by-byte from the format specs (no Android tooling),
  so the parsers are checked against independently-constructed bytes rather
  than against the tool that wrote them. `zipread` is additionally validated
  byte-identical to stdlib `zipfile` (entry listing, sizes, CRCs, bytes).
- **DEX integrity is checkable by hand.** The header's adler32 covers
  everything after the first 12 bytes and the SHA-1 covers everything after
  the first 32 — a single flipped byte is caught, which the test asserts.
- **Method refs + strings are enough for triage.** Class/method references
  catch `Runtime.exec` and friends; raw-string grepping catches API names that
  only appear as `const-string` operands (Dalvik has no imports table to lean
  on). Code items (`class_defs`) are deliberately not parsed — triage doesn't
  need them.

## Files

| File | What it does |
|---|---|
| `apktriage.py` | **Entry point**: triage CLI — manifest, DEX strings/APIs, URLs/IPs, verdict |
| `zipread.py` | Hand-rolled ZIP: EOCD back-scan, central directory, stored/deflated entries (inflate via stdlib `zlib`) |
| `axml.py` | Binary AndroidManifest.xml: string pool (UTF-8/UTF-16), resource map, namespaces, elements/attributes |
| `dex.py` | Dalvik DEX: header + adler32/SHA-1 verification, string/type/method tables |
| `build_fixture.py` | **Fixture only**: assembles `fixtures/evil.apk` + `fixtures/clean.apk` byte-by-byte (stdlib `zipfile` as writer only) |
| `test_apk.py` | 20-check battery, all deterministic |

## Limitations

- No ZIP64, multi-disk archives, encrypted entries, or data descriptors in
  `zipread` (central-directory sizes are authoritative for reading).
- `axml` resolves attribute values for the common `Res_value` types (string,
  int, boolean, hex); exotic typed values fall back to raw hex.
- `dex` does not parse `class_defs`/code items — triage works from the
  string and method-reference tables, which is where URLs, IPs and API
  references live.
- Verdict heuristics are deliberately simple (documented in `apktriage.py`):
  dynamic code loading, `Runtime.exec`, SMS-permission+SMS-API combos, and
  INTERNET+IP-literal URLs are SUSPICIOUS; anything else that fires is
  WORTH-A-LOOK. A genuinely malicious APK that hides its strings (packing,
  encryption) will look CLEAN to string grepping — that's a documented blind
  spot, not a clean bill of health.
