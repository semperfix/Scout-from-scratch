# Windows PE Executable Forensics (Skill 19)

Hand-rolled Windows PE parser plus a malware-triage engine. Zero dependencies, stdlib only. The parser handles DOS/NT/COFF headers, Optional headers (PE32 **and** PE32+), the section table, import/export tables (ILT/IAT, ordinals, hint/name), the debug directory (CodeView PDB paths), the security directory (Authenticode blob), base relocations, a 3-level resource tree walker, an overlay carver, and a from-scratch implementation of the PE checksum algorithm. `triage.py` scores CLEAN / SUSPICIOUS / MALICIOUS.

## Dependencies

Stdlib only (`struct`, `math`, …). No pip packages.

## Run

Entry point: `triage.py`.

```bash
cd pe-forensics
python3 triage.py <file.exe>          # verdict + scored findings + structural summary
python3 triage.py fixtures/benign.exe
python3 triage.py real-world.exe      # real signed PuTTY PE32+, ground-truth fixture
python3 test_pe.py                    # 40-check validation suite (fixtures + real-world.exe)
python3 pe_gen.py                     # rebuild the synthetic fixtures
```

## Usage example

```bash
$ python3 triage.py fixtures/evil_api.exe
fixtures/evil_api.exe: MALICIOUS (113 pts)
  [+30] suspicious import: VirtualAllocEx
  [+25] suspicious import: WriteProcessMemory
$ python3 triage.py real-world.exe
real-world.exe: CLEAN (8 pts)   # signed PuTTY, checksum valid, mundane imports
```

## Key learnings

- **The SECURITY directory is a file offset, not an RVA.** Every other data directory is an RVA; the cert table is the lone exception. A parser that treats it as an RVA reads garbage — the kind of spec asymmetry you only learn by implementing.
- **Entropy is a shape, not a verdict.** PuTTY's `.rsrc` hits 7.83 — the resource walk found a 365KB `ITSF`-magic blob (the embedded CHM help file). Triage now *identifies* (CHM/zip/MZ) before judging; only unidentified high-entropy blobs score.
- **The PE checksum covers the cert blob.** The hand-rolled implementation sums the whole file (minus the CheckSum field) and reproduces the linker's stored value byte-exact — empirical ground truth beats documentation.
- Triage is the totality, not any single indicator: a signed, checksum-valid binary with mundane imports nets out CLEAN even while individual findings (IsDebuggerPresent, RegSetValueEx) are still listed in the report.

## Files

- `triage.py` — entry point: scored CLEAN/SUSPICIOUS/MALICIOUS verdict engine
- `peparse.py` — the parser: headers, imports/exports, resources, overlay, checksum
- `pe_gen.py` — synthetic fixture builder (writes byte-correct PE32s from `struct` calls)
- `test_pe.py` — 40-check validation suite
- `real-world.exe` — actual signed PuTTY PE32+ (1.7 MB, downloaded) used as ground truth
- `fixtures/benign.exe`, `fixtures/packed.exe` (UPX-shaped), `fixtures/overlay.exe`, `fixtures/evil_api.exe`, `fixtures/exports.dll`, `fixtures/resource.exe` (hostile resources), `fixtures/cert.exe`, `fixtures/mangled.bin`, `fixtures/truncated.bin`
