#!/usr/bin/env python3
"""apktriage.py -- APK triage CLI (stdlib only).

Dissects an APK with the hand-rolled parsers (zipread / axml / dex) and
prints a verdict:

  * manifest: permissions, exported components, intent-filter attack surface
  * DEX strings: hardcoded URLs, IP literals
  * DEX method refs + strings: suspicious APIs (dynamic code loading,
    Runtime.exec, crypto, SMS)
  * verdict: CLEAN / WORTH-A-LOOK / SUSPICIOUS

Exit 0 always; the VERDICT: line is the machine-readable result.
"""
import argparse
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import zipread
import axml
import dex as dexmod

URL_RE = re.compile(rb"https?://[^\s\"'<>]+")
IP_RE = re.compile(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b")

DANGEROUS_PERMS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.RECEIVE_MMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.READ_EXTERNAL_STORAGE",
}

# (class-substring, method-substring-or-None, label)
SUSPICIOUS_APIS = [
    ("Ldalvik/system/DexClassLoader;", None, "dynamic code loading (DexClassLoader)"),
    ("Ldalvik/system/PathClassLoader;", None, "dynamic code loading (PathClassLoader)"),
    ("Ljava/lang/Runtime;", "exec", "command execution (Runtime.exec)"),
    ("Ljava/lang/ProcessBuilder;", None, "command execution (ProcessBuilder)"),
    ("Ljavax/crypto/Cipher;", None, "crypto API (Cipher)"),
    ("Landroid/telephony/SmsManager;", None, "SMS API (SmsManager)"),
    ("Landroid/telephony/SmsMessage;", None, "SMS API (SmsMessage)"),
    ("Ljava/net/HttpURLConnection;", None, "raw HTTP (HttpURLConnection)"),
    ("Ljavax/crypto/spec/SecretKeySpec;", None, "hardcoded crypto key material API"),
    ("Ljava/lang/reflect/Method;", "invoke", "reflection (Method.invoke)"),
]


def triage(apk_path):
    with open(apk_path, "rb") as f:
        data = f.read()
    report = {"file": apk_path, "signals": [], "notes": []}

    try:
        entries = zipread.list_entries(data)
    except zipread.ZipError as e:
        print("VERDICT: WORTH-A-LOOK -- not a readable ZIP: %s" % e)
        return
    report["entries"] = [(e.name, e.method, e.uncomp_size) for e in entries]
    names = [e.name for e in entries]

    # ---- manifest ----
    manifest = None
    if "AndroidManifest.xml" in names:
        try:
            mdata = zipread.read_name(data, "AndroidManifest.xml")
            manifest = axml.parse_axml(mdata)
        except (axml.AxmlError, zipread.ZipError) as e:
            report["notes"].append("manifest parse failed: %s" % e)
    else:
        report["notes"].append("no AndroidManifest.xml")

    perms, components = [], []
    if manifest:
        perms = manifest["permissions"]
        components = manifest["components"]
        report["package"] = manifest["package"]

    dangerous = [p for p in perms if p in DANGEROUS_PERMS]
    exported = [c for c in components
                if c["exported"] or (c["exported"] is None and c["intent_filters"])]
    if dangerous:
        report["signals"].append("dangerous permissions: %s"
                                 % ", ".join(dangerous))
    if exported:
        report["signals"].append(
            "exported attack surface: %s" % ", ".join(
                "%s %s%s" % (c["kind"], c["name"],
                             " (intent-filter)" if c["intent_filters"] else "")
                for c in exported))

    # ---- dex ----
    dex_files = [n for n in names
                 if re.fullmatch(r"classes\d*\.dex", n.split("/")[-1])]
    all_strings, all_methods = [], []
    for dn in dex_files:
        try:
            d = dexmod.parse_dex(zipread.read_name(data, dn))
        except (dexmod.DexError, zipread.ZipError) as e:
            report["notes"].append("dex parse failed for %s: %s" % (dn, e))
            continue
        all_strings.extend(d["strings"])
        all_methods.extend(d["methods"])
    report["n_strings"] = len(all_strings)
    report["n_methods"] = len(all_methods)

    blob = "\n".join(all_strings).encode("utf-8", "replace")
    urls = sorted(set(m.group(0).decode("utf-8", "replace")
                      for m in URL_RE.finditer(blob)))
    ips = sorted(set(m.group(0).decode() for m in IP_RE.finditer(blob)
                     if all(int(p) <= 255 for p in m.group(0).decode().split("."))))
    if urls:
        report["signals"].append("hardcoded URLs: %s" % ", ".join(urls))
    if ips:
        report["signals"].append("hardcoded IPs: %s" % ", ".join(ips))

    api_hits = []
    for cls_sub, meth_sub, label in SUSPICIOUS_APIS:
        for cls, meth in all_methods:
            if cls_sub in cls and (meth_sub is None or meth_sub in meth):
                api_hits.append(label)
                break
        else:
            # also grep raw strings (covers const-string references)
            if any(cls_sub.strip(";") in s for s in all_strings):
                if meth_sub is None or any(meth_sub in s for s in all_strings):
                    api_hits.append(label + " (string ref)")
    api_hits = sorted(set(api_hits))
    for h in api_hits:
        report["signals"].append("suspicious API: %s" % h)

    # ---- verdict ----
    labels = " ".join(api_hits)
    perms_set = set(perms)
    strong = (
        "DexClassLoader" in labels or "PathClassLoader" in labels or
        "Runtime.exec" in labels or
        ({"android.permission.READ_SMS", "android.permission.SEND_SMS"}
         & perms_set and "SmsManager" in labels) or
        ("android.permission.INTERNET" in perms_set and ips)
    )
    if strong:
        verdict = "SUSPICIOUS"
    elif report["signals"]:
        verdict = "WORTH-A-LOOK"
    else:
        verdict = "CLEAN"
    report["verdict"] = verdict
    return report


def print_report(r):
    print("file: %s" % r["file"])
    if r.get("package"):
        print("package: %s" % r["package"])
    print("zip entries: %d" % len(r["entries"]))
    for name, method, size in r["entries"]:
        print("  %-28s method=%s %d bytes" %
              (name, "deflated" if method == 8 else "stored", size))
    print("dex: %d strings, %d method refs" %
          (r["n_strings"], r["n_methods"]))
    if r["signals"]:
        print("signals:")
        for s in r["signals"]:
            print("  - %s" % s)
    for n in r["notes"]:
        print("note: %s" % n)
    print("VERDICT: %s%s" % (r["verdict"],
                             (" -- " + "; ".join(r["signals"])
                              if r["signals"] else "")))


def main():
    ap = argparse.ArgumentParser(
        description="Hand-rolled APK triage: manifest permissions, exported "
                    "components, hardcoded URLs/IPs, suspicious DEX APIs. "
                    "Stdlib only.")
    ap.add_argument("apk", help="APK file to triage")
    args = ap.parse_args()
    if not os.path.exists(args.apk):
        sys.exit("no such file: %s" % args.apk)
    r = triage(args.apk)
    if r:
        print_report(r)


if __name__ == "__main__":
    main()
