# OCI Container Image Forensics — Pull, Verify, and Triage Images from Scratch

A from-scratch toolkit for forensically pulling and analyzing OCI container
images: `tar.py` (~200 lines) is a hand-rolled tar parser with header-checksum
verification, GNU base-256 numerics, GNU `L`/`K` and pax `x` longname handling,
and strict end-of-archive discipline. `oci.py` (~450 lines) is a registry
client + layout parser + layer applier + triage engine: anonymous-token pull
from Docker Hub with the manifest `Docker-Content-Digest` verified against the
body, manifest-list platform selection, per-blob sha256 verification on
download, exact overlay semantics (`.wh.<name>` whiteouts delete a path,
`<dir>/.wh..wh..opq` opaque dirs wipe earlier children), Dockerfile
reconstruction from `history[].created_by`, and per-layer secret triage.
`ociforensic.py` is the CLI: `pull` / `triage` / `layers` / `dockerfile` /
`cat`.

The headline finding is that **whiteout ≠ deletion**: a file "removed" by a
later layer still exists in the lower layer's blob, so triage scans *every*
layer's blobs and reports `buried_secrets` — hits in layers where the file is
absent from the final tree (tested: secret in layer 0, whited out in layer 1
→ invisible to the final-tree scan, caught by the buried scan).

**Validation: `test_oci.py` 53/53** (tar round-trips for ustar/gnu/pax/prefix,
checksum-tamper and truncation rejection, base-256, whiteout/opaque semantics,
per-layer diff counts, digest-mismatch rejection, secret tiering,
buried-secret recovery, hardlink resolution). Live: pulled
`library/busybox:latest` (1 layer) and `library/python:3.13-alpine` (4 layers,
18.6 MiB) from Docker Hub — manifest digests, blob digests, and all 5
diff_ids verified against `sha256(uncompressed layer tar)`; triage output
reviewed by hand.

## Dependencies

Stdlib only. No pip packages. `pull` needs network access to the registry
(Docker Hub by default); everything else (`triage`, `layers`, `dockerfile`,
`cat`, tests) works fully offline on a pulled image directory.

## How to run

```
python3 test_oci.py                                    # 53/53 checks (offline)

python3 ociforensic.py pull library/busybox:latest ./busybox
python3 ociforensic.py triage ./busybox                 # secrets + chain of trust
python3 ociforensic.py layers ./busybox                 # per-layer added/modified/whiteouts
python3 ociforensic.py dockerfile ./busybox             # reconstructed Dockerfile
python3 ociforensic.py cat ./busybox etc/hostname       # read a file from the image
```

## Usage example

```python
import sys
sys.path.insert(0, ".")
import oci

# pull (needs network) then triage fully offline
r = oci.pull("library/busybox:latest", "/tmp/busybox")
tree, events = oci.apply_layers(r["layer_paths"])
blobs = oci.collect_all_blobs(r["layer_paths"])   # every layer's blobs, not just the final tree
finding = oci.triage(tree, oci.collect_blobs(tree, r["layer_paths"]),
                     r["config"], blobs)
print("buried secrets:", finding["buried_secrets"])
```

## Limitations

- **Layers must be gzip-compressed.** The layer applier runs
  `gzip.decompress` on every layer; zstd-compressed layers (legal in OCI) are
  not handled and will fail loudly.
- **Secret scanning is heuristic, and heuristics flag — humans judge.**
  Text-only scanning (blobs with NUL in the first 4 KiB are skipped, and
  vendor paths `/usr` `/lib` `/bin` `/sbin` `/opt` only run high-signal
  patterns) cut `python:3.13-alpine` from 48 hits to 2, but known residual
  false positives remain: `etc/nsswitch.conf` matches on `passwd: files`,
  `openssl.cnf` on the sample value `password = secret`.
- **Env-var triage surfaces, doesn't convict.** It caught `GPG_KEY` in
  python's image config — which is a *public* key ID, not a secret. Treat env
  hits as leads.
- **Digest verification covers transport + config chain, not signatures.**
  Manifest digest, per-blob digests, and the `diff_id == sha256(uncompressed
  tar)` chain are verified; there is no Notary/cosign/signature attestation.
- Anonymous Docker Hub auth only — the client hard-raises on any registry other
  than `registry-1.docker.io`, so private registries (and real credentials)
  are not supported.
- Tested against Docker Hub's registry behavior; other registries' quirks
  (different token endpoints, manifest-list shapes) are untested.
