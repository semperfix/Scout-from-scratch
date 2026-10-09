#!/usr/bin/env python3
"""ociforensic — pull and forensically triage OCI container images.

Usage:
  ociforensic.py pull <image> <destdir>     # e.g. pull library/busybox:latest ./busybox
  ociforensic.py triage <destdir>           # analyze a pulled image
  ociforensic.py layers <destdir>           # per-layer diff summary
  ociforensic.py dockerfile <destdir>       # reconstructed Dockerfile
  ociforensic.py cat <destdir> <path>       # print a file from the image
"""

import gzip
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import oci
import tar


def load_pull(destdir):
    meta = json.load(open(os.path.join(destdir, "manifest.json")))
    config = json.load(open(os.path.join(destdir, "config.json")))
    layers = sorted(f for f in os.listdir(destdir)
                    if f.startswith("layer-") and f.endswith(".tar.gz"))
    layer_paths = [os.path.join(destdir, f) for f in layers]
    return meta, config, layer_paths


def cmd_pull(image, destdir):
    def progress(i, n):
        sys.stderr.write(f"\rlayer {i}: {n // 1024} KiB")
    r = oci.pull(image, destdir, progress=progress)
    sys.stderr.write("\n")
    print(f"pulled {image}")
    print(f"  digest: {r['digest']}")
    print(f"  config: {r['config']['architecture']}/{r['config'].get('os')}")
    for i, lp in enumerate(r["layer_paths"]):
        print(f"  layer {i}: {os.path.getsize(lp) // 1024} KiB  "
              f"{r['manifest']['layers'][i]['digest'][:19]}...")


def cmd_triage(destdir):
    meta, config, layer_paths = load_pull(destdir)
    tree, events = oci.apply_layers(layer_paths)
    diff = oci.diff_layers(tree, events)
    blobs = oci.collect_blobs(tree, layer_paths)
    all_blobs = oci.collect_all_blobs(layer_paths)
    f = oci.triage(tree, blobs, config, all_blobs)

    nfiles = sum(1 for n in tree.nodes.values() if n["kind"] == "file")
    ndirs = sum(1 for n in tree.nodes.values() if n["kind"] == "dir")
    nhard = sum(1 for n in tree.nodes.values() if n["kind"] == "hardlink")
    nsym = sum(1 for n in tree.nodes.values() if n["kind"] == "symlink")
    print(f"image digest: {meta['digest']}")
    print(f"layers: {len(layer_paths)}   files: {nfiles}   hardlinks: {nhard} "
          f"symlinks: {nsym}   dirs: {ndirs}")
    # chain of trust: manifest -> config -> diff_id == sha256(uncompressed layer)
    import hashlib
    diff_ids = config.get("rootfs", {}).get("diff_ids", [])
    chain_ok = True
    for lp, want in zip(layer_paths, diff_ids):
        got = "sha256:" + hashlib.sha256(
            gzip.decompress(open(lp, "rb").read())).hexdigest()
        if got != want:
            chain_ok = False
            print(f"  DIFF_ID MISMATCH layer {lp}: {got} != {want}")
    print(f"diff_id chain: {'OK' if chain_ok else 'BROKEN'} "
          f"({len(diff_ids)} verified)")
    print(f"created: {config.get('created')}")
    cfg = config.get("config") or {}
    print(f"entrypoint: {cfg.get('Entrypoint')}  cmd: {cfg.get('Cmd')}")
    print(f"user: {cfg.get('User') or '(root)'}  workdir: {cfg.get('WorkingDir') or '/'}")
    print(f"exposed: {list((cfg.get('ExposedPorts') or {}).keys()) or 'none'}")
    print("\n-- layer diff --")
    for d in diff:
        wo = sum(c for _, c in d["whiteouts"])
        print(f"  layer {d['layer']}: +{d['added']} ~{d['modified']} "
              f"whiteouts={len(d['whiteouts'])}/{wo} opaques={len(d['opaques'])}")
        for tgt, c in d["whiteouts"][:5]:
            print(f"      wh {tgt} (removed {c})")
    print("\n-- triage --")
    for label in ("secrets", "buried_secrets", "setuid", "setgid",
                  "world_writable", "ssh_dirs", "extra_root_users",
                  "big_files", "config_env_secrets"):
        vals = f.get(label, [])
        print(f"  {label}: {len(vals)}")
        for v in vals[:10]:
            print(f"      {v}")


def cmd_layers(destdir):
    meta, config, layer_paths = load_pull(destdir)
    tree, events = oci.apply_layers(layer_paths)
    diff = oci.diff_layers(tree, events)
    hist = [h for h in config.get("history", []) if not h.get("empty_layer")]
    for d in diff:
        print(f"layer {d['layer']}: +{d['added']} ~{d['modified']} "
              f"whiteouts={len(d['whiteouts'])} opaques={len(d['opaques'])}")
        if d["layer"] < len(hist):
            print(f"    by: {(hist[d['layer']].get('created_by') or '')[:100]}")


def cmd_dockerfile(destdir):
    _, config, _ = load_pull(destdir)
    for line in oci.reconstruct_dockerfile(config):
        print(line)


def _resolve(tree, path, blobs):
    """Follow symlink/hardlink chains to final content bytes."""
    seen = set()
    p = path
    while True:
        if p in seen:
            return None
        seen.add(p)
        node = tree.nodes.get(p)
        if not node:
            return None
        if node["kind"] in ("file", "hardlink"):
            return blobs.get(p)
        if node["kind"] == "symlink":
            t = node["target"]
            p = t.lstrip("/") if t.startswith("/") else \
                (p.rsplit("/", 1)[0] + "/" + t if "/" in p else t)
            p = oci._norm(p)
        else:
            return None


def cmd_cat(destdir, path):
    _, _, layer_paths = load_pull(destdir)
    tree, _ = oci.apply_layers(layer_paths)
    blobs = oci.collect_blobs(tree, layer_paths)
    data = _resolve(tree, path.lstrip("/"), blobs)
    if data is None:
        print(f"not a resolvable file in image: {path}", file=sys.stderr)
        sys.exit(1)
    sys.stdout.buffer.write(data)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(2)
    cmd = sys.argv[1]
    if cmd == "pull" and len(sys.argv) == 4:
        cmd_pull(sys.argv[2], sys.argv[3])
    elif cmd == "triage" and len(sys.argv) == 3:
        cmd_triage(sys.argv[2])
    elif cmd == "layers" and len(sys.argv) == 3:
        cmd_layers(sys.argv[2])
    elif cmd == "dockerfile" and len(sys.argv) == 3:
        cmd_dockerfile(sys.argv[2])
    elif cmd == "cat" and len(sys.argv) == 4:
        cmd_cat(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)
        sys.exit(2)
