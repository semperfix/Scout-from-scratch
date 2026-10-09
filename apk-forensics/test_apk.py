#!/usr/bin/env python3
"""test_apk.py -- validate the hand-rolled APK stack.

  * zipread vs stdlib zipfile: entry listing + byte-identical extraction on
    the fixture APKs and on a generated mixed (stored/deflated) zip.
  * axml: fixture manifest parses to the expected permissions/components.
  * dex: strings/method refs extracted; adler32 + SHA-1 integrity verified;
    a tampered DEX is rejected.
  * apktriage: evil fixture -> SUSPICIOUS, clean fixture -> CLEAN.
  * CLI smoke: --help, both fixtures exit 0 with a VERDICT line.
"""
import os
import random
import subprocess
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import zipread
import axml
import dex as dexmod
import build_fixture
from apktriage import triage

FIXDIR = os.path.join(HERE, "fixtures")
EVIL = os.path.join(FIXDIR, "evil.apk")
CLEAN = os.path.join(FIXDIR, "clean.apk")
CLI = os.path.join(HERE, "apktriage.py")

checks = []


def check(name, cond, detail=""):
    checks.append((name, bool(cond)))
    print(("PASS " if cond else "FAIL ") + name +
          (" -- " + str(detail) if detail and not cond else ""))


def compare_zip(path):
    """zipread must agree with stdlib zipfile on listing + bytes."""
    with open(path, "rb") as f:
        data = f.read()
    entries = zipread.list_entries(data)
    with zipfile.ZipFile(path) as z:
        infos = z.infolist()
        names_a = sorted(e.name for e in entries)
        names_b = sorted(i.filename for i in infos)
        if names_a != names_b:
            return False, "name lists differ: %s vs %s" % (names_a, names_b)
        for e in entries:
            a = zipread.read_entry(data, e)
            b = z.read(e.name)
            if a != b:
                return False, "bytes differ for %s" % e.name
            info = next(i for i in infos if i.filename == e.name)
            if e.comp_size != info.compress_size or \
               e.uncomp_size != info.file_size or \
               e.crc32 != info.CRC:
                return False, "metadata differ for %s" % e.name
    return True, ""


def main():
    build_fixture.main()

    for apk in (EVIL, CLEAN):
        ok, detail = compare_zip(apk)
        check("zipread == zipfile (%s)" % os.path.basename(apk), ok, detail)

    # generated mixed zip: stored + deflated, empty files, nested dirs
    rnd = os.path.join(FIXDIR, "random.zip")
    random.seed(42)
    with zipfile.ZipFile(rnd, "w") as z:
        for i in range(60):
            blob = bytes(random.randrange(256) for _ in range(random.randrange(0, 3000)))
            z.writestr("dir%d/file%02d.bin" % (i % 5, i), blob,
                       compress_type=random.choice(
                           (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)))
        z.writestr("empty.txt", b"", compress_type=zipfile.ZIP_STORED)
    ok, detail = compare_zip(rnd)
    check("zipread == zipfile (random 61-entry zip)", ok, detail)

    # axml on the evil manifest
    with open(EVIL, "rb") as f:
        edata = f.read()
    m = axml.parse_axml(zipread.read_name(edata, "AndroidManifest.xml"))
    check("manifest package", m["package"] == "com.evil.flashlight", m["package"])
    check("manifest permissions",
          sorted(m["permissions"]) == ["android.permission.INTERNET",
                                       "android.permission.READ_SMS"],
          m["permissions"])
    acts = [c for c in m["components"] if c["kind"] == "activity"]
    check("exported activity w/ intent-filter",
          len(acts) == 1 and acts[0]["exported"] is True and
          acts[0]["intent_filters"] == 1, acts)
    mc = axml.parse_axml(zipread.read_name(open(CLEAN, "rb").read(),
                                           "AndroidManifest.xml"))
    check("clean manifest has no permissions", mc["permissions"] == [],
          mc["permissions"])
    cacts = [c for c in mc["components"] if c["kind"] == "activity"]
    check("clean activity not exported",
          len(cacts) == 1 and not cacts[0]["exported"] and
          cacts[0]["intent_filters"] == 0, cacts)

    # dex
    d = dexmod.parse_dex(zipread.read_name(edata, "classes.dex"))
    check("dex strings extracted",
          "http://evil.example.com/collect" in d["strings"] and
          "Ldalvik/system/DexClassLoader;" in d["strings"],
          "%d strings" % len(d["strings"]))
    check("dex method refs extracted",
          ("Ljava/lang/Runtime;", "exec") in d["methods"] and
          ("Lcom/evil/Loader;", "loadDex") in d["methods"],
          d["methods"])
    tampered = bytearray(zipread.read_name(edata, "classes.dex"))
    tampered[0x80] ^= 0xFF
    try:
        dexmod.parse_dex(bytes(tampered))
        check("tampered dex rejected", False, "no error raised")
    except dexmod.DexError:
        check("tampered dex rejected", True)

    # triage verdicts
    r = triage(EVIL)
    check("evil.apk verdict SUSPICIOUS", r["verdict"] == "SUSPICIOUS",
          r["verdict"])
    sig = " ".join(r["signals"])
    for needle in ("DexClassLoader", "Runtime.exec",
                   "android.permission.READ_SMS", "evil.example.com"):
        check("evil signal: %s" % needle, needle in sig, sig[:200])
    r = triage(CLEAN)
    check("clean.apk verdict CLEAN", r["verdict"] == "CLEAN",
          "%s: %s" % (r["verdict"], r["signals"]))

    # CLI smoke
    for apk in (EVIL, CLEAN):
        p = subprocess.run([sys.executable, CLI, apk],
                           capture_output=True, text=True)
        check("cli exits 0 + VERDICT (%s)" % os.path.basename(apk),
              p.returncode == 0 and "VERDICT:" in p.stdout, p.stderr[:200])
    p = subprocess.run([sys.executable, CLI, "--help"],
                       capture_output=True, text=True)
    check("cli --help", p.returncode == 0 and "usage" in p.stdout.lower())

    failed = [n for n, ok in checks if not ok]
    print("\n%d/%d checks passed" % (len(checks) - len(failed), len(checks)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
