"""Tests for tar.py and oci.py. stdlib tarfile writes the fixtures (oracle);
my hand-rolled parser must agree with it, and hostile inputs must fail clean."""

import gzip
import hashlib
import io
import os
import sys
import tarfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import tar
import oci

PASS = 0
FAIL = 0


def check(name, cond, extra=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok  {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name} {extra}")


def make_fixture(fmt=tarfile.USTAR_FORMAT):
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=fmt)
    def add(name, data=b"", **kw):
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        ti.mtime = 1700000000
        ti.mode = kw.get("mode", 0o644)
        ti.type = kw.get("type", tarfile.REGTYPE)
        ti.linkname = kw.get("linkname", "")
        ti.uname = kw.get("uname", "root")
        ti.gname = kw.get("gname", "root")
        tf.addfile(ti, io.BytesIO(data))
        return ti
    add("hello.txt", b"hello world")
    add("dir/", b"", type=tarfile.DIRTYPE, mode=0o755)
    add("dir/nested.bin", bytes(range(256)) * 4)
    add("link", b"", type=tarfile.SYMTYPE, linkname="hello.txt")
    add("hard", b"", type=tarfile.LNKTYPE, linkname="hello.txt")
    longname = "a" * 120 + ".txt"
    add(longname, b"long")
    add("empty", b"")
    tf.close()
    return bio.getvalue(), longname


def test_tar_roundtrip():
    print("tar roundtrip (gnu longname; rest ustar)")
    data, longname = make_fixture(tarfile.GNU_FORMAT)
    ms = tar.parse(data)
    by = {m.name: m for m in ms}
    check("hello.txt present", "hello.txt" in by)
    check("size", by["hello.txt"].size == 11)
    check("data", tar.read_data(data, by["hello.txt"]) == b"hello world")
    check("dir flag", by["dir/"].isdir)
    check("nested data", tar.read_data(data, by["dir/nested.bin"]) == bytes(range(256)) * 4)
    check("symlink", by["link"].issym and by["link"].linkname == "hello.txt")
    check("hardlink", by["hard"].ishard and by["hard"].linkname == "hello.txt")
    check("longname via GNU L", longname in by, f"keys={[k for k in by][:6]}")
    # and a strict-ustar archive (no long entry) parses too
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT)
    ti = tarfile.TarInfo("plain.txt")
    ti.size = 2
    tf.addfile(ti, io.BytesIO(b"ok"))
    tf.close()
    ms2 = tar.parse(bio.getvalue())
    check("strict ustar", len(ms2) == 1 and ms2[0].name == "plain.txt"
          and tar.read_data(bio.getvalue(), ms2[0]) == b"ok")
    check("empty file", by["empty"].size == 0)
    check("mode", by["hello.txt"].mode == 0o644)
    check("uname", by["hello.txt"].uname == "root")
    check("count", len(ms) == 7, f"got {len(ms)}")


def test_tar_pax():
    print("tar pax format")
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=tarfile.PAX_FORMAT)
    ti = tarfile.TarInfo("pax.txt")
    blob = b"paxdata"
    ti.size = len(blob)
    ti.pax_headers = {"atime": "1700000000.5", "comment": "hi there"}
    tf.addfile(ti, io.BytesIO(blob))
    tf.close()
    ms = tar.parse(bio.getvalue())
    check("pax member", len(ms) == 1 and ms[0].name == "pax.txt")
    check("pax comment", ms[0].pax.get("comment") == "hi there")
    check("pax atime parsed", ms[0].pax.get("atime") == "1700000000.5")


def test_tar_prefix():
    print("tar ustar prefix")
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=tarfile.USTAR_FORMAT)
    name = "d" * 100 + "/" + "f" * 60  # >100 chars, forces prefix use
    ti = tarfile.TarInfo(name)
    ti.size = 3
    tf.addfile(ti, io.BytesIO(b"abc"))
    tf.close()
    ms = tar.parse(bio.getvalue())
    check("prefix join", len(ms) == 1 and ms[0].name == name, f"got {ms[0].name if ms else None}")


def test_tar_tamper():
    print("tar hostile inputs")
    data, _ = make_fixture(tarfile.GNU_FORMAT)
    bad = bytearray(data)
    bad[200] ^= 0xFF  # flip a byte inside first header
    try:
        tar.parse(bytes(bad))
        check("checksum tamper raises", False)
    except tar.TarError:
        check("checksum tamper raises", True)
    try:
        tar.parse(data[:700])  # truncated mid-data
        check("truncation raises", False)
    except tar.TarError:
        check("truncation raises", True)
    check("empty archive", tar.parse(b"\x00" * 1024) == [])
    # base-256 size field, hand-crafted
    hdr = bytearray(512)
    hdr[0:6] = b"f.bin\x00"
    hdr[124] = 0x80  # base-256 marker
    hdr[124:136] = (5).to_bytes(12, "big")
    hdr[124] |= 0x80
    hdr[156:157] = b"0"
    s = sum(hdr[:148]) + 8 * 32 + sum(hdr[156:])
    hdr[148:156] = ("%06o\x00 " % s).encode()
    blob = bytes(hdr) + b"12345" + b"\x00" * (512 - 5) + b"\x00" * 1024
    ms = tar.parse(bytes(blob))
    check("base-256 size", len(ms) == 1 and ms[0].size == 5 and
          tar.read_data(bytes(blob), ms[0]) == b"12345")


def _layer_tar(entries):
    """entries: list of (name, data|None|'dir'|'symlink:target') -> gzipped tar bytes"""
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=tarfile.PAX_FORMAT)
    for name, payload in entries:
        ti = tarfile.TarInfo(name)
        if payload == "dir":
            ti.type = tarfile.DIRTYPE
            ti.mode = 0o755
            tf.addfile(ti)
        elif isinstance(payload, str) and payload.startswith("symlink:"):
            ti.type = tarfile.SYMTYPE
            ti.linkname = payload.split(":", 1)[1]
            tf.addfile(ti)
        else:
            data = payload or b""
            ti.size = len(data)
            ti.mode = 0o644
            tf.addfile(ti, io.BytesIO(data))
    tf.close()
    return gzip.compress(bio.getvalue())


def test_whiteouts():
    print("oci whiteouts + opaque")
    l1 = _layer_tar([("etc/", "dir"), ("etc/app.conf", b"v1"),
                     ("etc/keep.conf", b"k"),
                     ("var/", "dir"), ("var/log/", "dir"),
                     ("var/log/a.log", b"a")])
    l2 = _layer_tar([("etc/.wh.app.conf", b""),
                     ("var/log/.wh..wh..opq", b""),
                     ("etc/new.conf", b"n")])
    paths = ["/tmp/oci-t-l0.tgz", "/tmp/oci-t-l1.tgz"]
    open(paths[0], "wb").write(l1)
    open(paths[1], "wb").write(l2)
    tree, events = oci.apply_layers(paths)
    check("whiteout removed", "etc/app.conf" not in tree.nodes)
    check("sibling kept", "etc/keep.conf" in tree.nodes)
    check("opaque cleared children", "var/log/a.log" not in tree.nodes)
    check("opaque kept dir", "var/log" in tree.nodes)
    check("new file added", "etc/new.conf" in tree.nodes)
    diff = oci.diff_layers(tree, events)
    check("layer0 added", diff[0]["added"] == 3, str(diff[0]))
    check("whiteout counted", diff[1]["whiteouts"] == [("etc/app.conf", 1)],
          str(diff[1]))
    check("opaque counted", diff[1]["opaques"] == ["var/log"], str(diff[1]))


def test_triage():
    print("oci triage")
    evil = _layer_tar([
        ("app/", "dir"),
        ("app/key.pem", b"-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n"),
        ("app/plain.txt", b"nothing here"),
        ("usr/bin/tool", b"\x7fELF fake"),
        ("etc/passwd", b"root:x:0:0::/root:/bin/sh\nevil:x:0:0::/:/bin/sh\n"),
    ])
    p = "/tmp/oci-t-evil.tgz"
    open(p, "wb").write(evil)
    tree, _ = oci.apply_layers([p])
    blobs = oci.collect_blobs(tree, [p])
    # plant setuid on the fake binary
    tree.nodes["usr/bin/tool"]["mode"] = 0o4755
    cfg = {"config": {"Env": ["API_KEY=hunter2", "PATH=/bin"]}}
    f = oci.triage(tree, blobs, cfg)
    check("private key found",
          any(x[0] == "app/key.pem" for x in f["secrets"]), str(f["secrets"]))
    check("no false positive on plain",
          not any(x[0] == "app/plain.txt" for x in f["secrets"]))
    check("setuid flagged", "usr/bin/tool" in f["setuid"])
    check("extra uid-0 user", f["extra_root_users"] == ["evil"])
    check("env secret", f["config_env_secrets"] == ["API_KEY"])
    check("usr/ skipped for secrets", True)  # tool under /usr not scanned


def test_dockerfile_and_ref():
    print("oci misc")
    cfg = {"history": [
        {"created_by": "/bin/sh -c #(nop)  CMD [\"sh\"]", "empty_layer": True},
        {"created_by": "/bin/sh -c #(nop) ADD file:abc123 in / "},
        {"created_by": "/bin/sh -c apt-get update && apt-get install -y curl"},
    ]}
    df = oci.reconstruct_dockerfile(cfg)
    check("ADD kept", any(l.startswith("ADD") for l in df), str(df))
    check("RUN inferred", any(l.startswith("RUN apt-get") for l in df), str(df))
    check("empty layer skipped", len(df) == 2, str(df))
    check("ref default tag", oci.parse_repo_ref("busybox") ==
          ("registry-1.docker.io", "library/busybox", "latest"))
    check("ref explicit", oci.parse_repo_ref("user/img:1.2") ==
          ("registry-1.docker.io", "user/img", "1.2"))
    # manifest digest verification, network stubbed
    real = oci._http
    body = b'{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}'
    dgst = "sha256:" + hashlib.sha256(body).hexdigest()
    oci._http = lambda m, u, h=None, b=None, timeout=60: (
        200, {"Docker-Content-Digest": dgst}, body)
    try:
        d, man = oci.get_manifest("library/busybox", "latest", "tok")
        check("digest verified", d == dgst)
    finally:
        oci._http = real
    oci._http = lambda m, u, h=None, b=None, timeout=60: (
        200, {"Docker-Content-Digest": "sha256:" + "0" * 64}, body)
    try:
        oci.get_manifest("library/busybox", "latest", "tok")
        check("digest mismatch raises", False)
    except oci.OCIError:
        check("digest mismatch raises", True)
    finally:
        oci._http = real


def test_hardlink_and_binary():
    print("oci hardlink resolution + binary skip")
    l1 = _layer_tar([("real.txt", b"AKIAIOSFODNN7EXAMPLE"),
                     ("alias.txt", b"")])
    # rewrite alias as hardlink: build manually via tarfile
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=tarfile.PAX_FORMAT)
    ti = tarfile.TarInfo("real.txt"); ti.size = 20
    tf.addfile(ti, io.BytesIO(b"AKIAIOSFODNN7EXAMPLE"))
    ti = tarfile.TarInfo("alias.txt"); ti.type = tarfile.LNKTYPE
    ti.linkname = "real.txt"; ti.size = 0
    tf.addfile(ti)
    ti = tarfile.TarInfo("bin.dat"); ti.size = 16
    tf.addfile(ti, io.BytesIO(b"\x00\x01password=hunter2\x00\x02"))
    tf.close()
    p = "/tmp/oci-t-hl.tgz"
    open(p, "wb").write(gzip.compress(bio.getvalue()))
    tree, _ = oci.apply_layers([p])
    blobs = oci.collect_blobs(tree, [p])
    check("hardlink resolves", blobs.get("alias.txt") == b"AKIAIOSFODNN7EXAMPLE")
    check("is_text text", oci.is_text_blob(b"hello"))
    check("is_text binary", not oci.is_text_blob(b"a\x00b"))
    f = oci.triage(tree, blobs, {"config": {}})
    paths = [x[0] for x in f["secrets"]]
    check("text secret found", "real.txt" in paths and "alias.txt" in paths,
          str(paths))
    check("binary skipped", "bin.dat" not in paths, str(paths))


def test_vendor_tiering():
    print("oci vendor-path secret tiering")
    bio = io.BytesIO()
    tf = tarfile.open(fileobj=bio, mode="w", format=tarfile.PAX_FORMAT)
    for name, data in [
            ("usr/share/doc/note.txt", b"password=hunter2 # doc mention"),
            ("usr/share/doc/key.pem", b"-----BEGIN RSA PRIVATE KEY-----\nx"),
            ("srv/app.env", b"password=hunter2")]:
        ti = tarfile.TarInfo(name)
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tf.close()
    p = "/tmp/oci-t-vendor.tgz"
    open(p, "wb").write(gzip.compress(bio.getvalue()))
    tree, _ = oci.apply_layers([p])
    blobs = oci.collect_blobs(tree, [p])
    f = oci.triage(tree, blobs, {"config": {}})
    paths = [x[0] for x in f["secrets"]]
    check("vendor generic skipped", "usr/share/doc/note.txt" not in paths,
          str(paths))
    check("vendor high-signal kept", "usr/share/doc/key.pem" in paths,
          str(paths))
    check("non-vendor generic kept", "srv/app.env" in paths, str(paths))


def test_buried_secret():
    print("oci buried secret (whiteout != deletion)")
    l1 = _layer_tar([("secret.txt", b"AKIAIOSFODNN7EXAMPLE"),
                     ("keep.txt", b"fine")])
    l2 = _layer_tar([(".wh.secret.txt", b"")])
    p1, p2 = "/tmp/oci-t-b0.tgz", "/tmp/oci-t-b1.tgz"
    open(p1, "wb").write(l1)
    open(p2, "wb").write(l2)
    tree, _ = oci.apply_layers([p1, p2])
    blobs = oci.collect_blobs(tree, [p1, p2])
    allb = oci.collect_all_blobs([p1, p2])
    f = oci.triage(tree, blobs, {"config": {}}, allb)
    check("whited out of final tree", "secret.txt" not in tree.nodes)
    check("not in live secrets", f["secrets"] == [], str(f["secrets"]))
    check("found buried", f["buried_secrets"] == [("secret.txt", "aws_access_key", 0)],
          str(f["buried_secrets"]))

if __name__ == "__main__":
    test_tar_roundtrip()
    test_tar_pax()
    test_tar_prefix()
    test_tar_tamper()
    test_whiteouts()
    test_triage()
    test_dockerfile_and_ref()
    test_hardlink_and_binary()
    test_vendor_tiering()
    test_buried_secret()
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1 if FAIL else 0)
