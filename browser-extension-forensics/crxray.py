#!/usr/bin/env python3
"""
crxray — browser extension forensics, from scratch.

What it does:
  1. Parses the CRX3 package format by hand (magic, protobuf header, crx_id
     derivation per the Chromium spec) — no libraries.
  2. Can *write* CRX3 files too (test-fixture builder), proving the parse.
  3. Reads the ZIP payload via a hand-rolled central-directory walker.
  4. Analyzes manifest.json (MV2 + MV3): permission risk model, host patterns,
     background/service-worker, web_accessible_resources, update_url, CSP.
  5. Statically scans JS for malicious sinks: cookie theft, keylogging,
     webRequest interception, debugger abuse, eval, exfiltration URLs.
  6. Produces a triage verdict: CLEAN / SUSPICIOUS / MALICIOUS with reasons.

No third-party dependencies. Python 3.8+.
"""
import hashlib
import json
import os
import re
import struct
import sys

# ---------------------------------------------------------------------------
# 1. Minimal protobuf codec (hand-rolled).
#    Only what CRX3 needs: varint, 64-bit, length-delimited, 32-bit.
# ---------------------------------------------------------------------------

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        if pos >= len(buf):
            raise ValueError("truncated varint")
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7
        if shift > 70:
            raise ValueError("varint too long")


def proto_decode(buf):
    """Decode a protobuf message into [(field_number, wire_type, value)]."""
    fields = []
    pos = 0
    while pos < len(buf):
        key, pos = _read_varint(buf, pos)
        field_no, wire_type = key >> 3, key & 0x07
        if wire_type == 0:                      # varint
            val, pos = _read_varint(buf, pos)
        elif wire_type == 1:                   # 64-bit
            val = buf[pos:pos + 8]; pos += 8
        elif wire_type == 2:                   # length-delimited
            ln, pos = _read_varint(buf, pos)
            val = bytes(buf[pos:pos + ln]); pos += ln
        elif wire_type == 5:                   # 32-bit
            val = buf[pos:pos + 4]; pos += 4
        else:
            raise ValueError(f"unsupported wire type {wire_type}")
        fields.append((field_no, wire_type, val))
    return fields


def _enc_varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def proto_field(field_no, wire_type, payload):
    """Encode one field. payload: int for varint, bytes for len-delimited."""
    head = _enc_varint((field_no << 3) | wire_type)
    if wire_type == 0:
        return head + _enc_varint(payload)
    if wire_type == 2:
        return head + _enc_varint(len(payload)) + payload
    raise ValueError("only varint/len-delimited supported for encode")


def proto_msg(*field_bytes):
    return b"".join(field_bytes)

# ---------------------------------------------------------------------------
# 2. CRX3 packaging internals.
#
#   offset 0:  magic "Cr24" (4 bytes)
#   offset 4:  version = 3 (uint32 LE)
#   offset 8:  header length N (uint32 LE)
#   offset 12: CrxFileHeader protobuf (N bytes):
#                field 1 (repeated, len-delim): AsymmetricKeyProof {
#                         field 1 (len-delim): public_key (DER bytes) }
#                field 3 (len-delim): signed_header_data = SignedData {
#                         field 1 (len-delim): crx_id (16 bytes) }
#   offset 12+N: the ZIP payload.
#
#   crx_id = SHA256(public_key_der)[:16]
#   The 32-char Web Store id ("cjpalhdlnbpafiamejdnhcphjbkeiagm") is each
#   nibble of crx_id mapped onto 'a'..'p'.
# ---------------------------------------------------------------------------

CRX_MAGIC = b"Cr24"
CRX_VERSION = 3


def crx_id_from_pubkey(pubkey_der):
    return hashlib.sha256(pubkey_der).digest()[:16]


def crx_id_to_string(crx_id):
    return "".join(chr(ord("a") + ((b >> 4) & 0xF)) + chr(ord("a") + (b & 0xF))
                   for b in crx_id)


def parse_crx3(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 12:
        raise ValueError("file too small for CRX header")
    magic, version, header_len = data[:4], struct.unpack("<I", data[4:8])[0], \
        struct.unpack("<I", data[8:12])[0]
    if magic != CRX_MAGIC:
        raise ValueError(f"bad magic {magic!r} (not a CRX)")
    if version != CRX_VERSION:
        raise ValueError(f"unsupported CRX version {version}")
    header = data[12:12 + header_len]
    if len(header) != header_len:
        raise ValueError("truncated CRX header")
    pubkeys, signed = [], None
    for fno, wt, val in proto_decode(header):
        if fno == 1 and wt == 2:                       # AsymmetricKeyProof
            for sfno, swt, sval in proto_decode(val):
                if sfno == 1 and swt == 2:
                    pubkeys.append(bytes(sval))
        elif fno == 3 and wt == 2:                     # signed_header_data
            for sfno, swt, sval in proto_decode(val):
                if sfno == 1 and swt == 2:
                    signed = bytes(sval)               # crx_id
    derived = [crx_id_from_pubkey(k) for k in pubkeys]
    return {
        "magic": magic, "version": version,
        "header_len": header_len,
        "public_keys": pubkeys,
        "crx_id_embedded": signed,
        "crx_id_derived": derived,
        "crx_id_match": bool(signed) and signed in derived,
        "extension_id": crx_id_to_string(signed) if signed else None,
        "zip_offset": 12 + header_len,
        "zip_bytes": data[12 + header_len:],
    }


def build_crx3(pubkey_der, zip_bytes):
    """Write a CRX3 file (unsigned proof — fine for forensics fixtures)."""
    crx_id = crx_id_from_pubkey(pubkey_der)
    signed_data = proto_msg(proto_field(1, 2, crx_id))
    proof = proto_msg(proto_field(1, 2, pubkey_der))   # no signature
    header = proto_msg(proto_field(1, 2, proof),
                       proto_field(3, 2, signed_data))
    return CRX_MAGIC + struct.pack("<II", CRX_VERSION, len(header)) + \
        header + zip_bytes

# ---------------------------------------------------------------------------
# 3. Hand-rolled ZIP reader (central directory walk).
#    Enough for forensics triage: list names, read file bytes (stored +
#    deflated), detect anomalies (name tricks, huge files).
# ---------------------------------------------------------------------------
import zlib

EOCD_SIG = 0x06054B50
CD_SIG = 0x02014B50
LF_SIG = 0x04034B50


def _find_eocd(data):
    # EOCD is at the end; comment can push it back up to 64k.
    start = max(0, len(data) - 66000)
    idx = data.rfind(struct.pack("<I", EOCD_SIG), start)
    if idx < 0:
        raise ValueError("EOCD not found — not a ZIP")
    return idx


def zip_entries(data):
    eocd = _find_eocd(data)
    # EOCD: sig(4) disk(2) cd_disk(2) cd_this(2) cd_total(2) size(4) off(4)
    cd_count = struct.unpack("<H", data[eocd + 10:eocd + 12])[0]
    cd_off = struct.unpack("<I", data[eocd + 16:eocd + 20])[0]
    entries = []
    pos = cd_off
    for _ in range(cd_count):
        if struct.unpack("<I", data[pos:pos + 4])[0] != CD_SIG:
            raise ValueError("bad central directory signature")
        (made_by, needed, flags, method, mod_t, mod_d, crc, csize, usize,
         nlen, elen, clen, disk, iattr, eattr, lho) = struct.unpack(
            "<HHHHHHIIIHHHHHII", data[pos + 4:pos + 46])
        name = data[pos + 46:pos + 46 + nlen].decode("utf-8", "replace")
        entries.append({"name": name, "method": method, "csize": csize,
                        "usize": usize, "crc": crc, "lho": lho})
        pos += 46 + nlen + elen + clen
    return entries


def zip_read(data, entry):
    pos = entry["lho"]
    if struct.unpack("<I", data[pos:pos + 4])[0] != LF_SIG:
        raise ValueError("bad local header")
    nlen, elen = struct.unpack("<HH", data[pos + 26:pos + 30])
    start = pos + 30 + nlen + elen
    raw = data[start:start + entry["csize"]]
    if entry["method"] == 0:
        return raw
    if entry["method"] == 8:
        return zlib.decompress(raw, -15)
    raise ValueError(f"unsupported compression method {entry['method']}")


def zip_name_map(data):
    entries = zip_entries(data)
    return {e["name"]: e for e in entries}

# ---------------------------------------------------------------------------
# 4. manifest.json analysis (MV2 + MV3).
# ---------------------------------------------------------------------------

# permission -> (risk points, why)
PERM_RISK = {
    "cookies": (25, "can read/modify ALL browser cookies incl. session tokens"),
    "history": (20, "can read full browsing history"),
    "bookmarks": (15, "can read/modify bookmarks"),
    "webRequest": (15, "can observe every network request"),
    "webRequestBlocking": (25, "can intercept/modify/block network traffic"),
    "declarativeNetRequest": (8, "can block/redirect requests via rulesets"),
    "debugger": (30, "can attach debugger to tabs = full page control"),
    "proxy": (25, "can reroute ALL browser traffic through attacker proxy"),
    "management": (20, "can install/enable/disable other extensions"),
    "privacy": (15, "can weaken browser privacy/security settings"),
    "tabs": (8, "can read URLs/titles of open tabs"),
    "activeTab": (3, "temporary access to active tab on user click"),
    "scripting": (12, "can inject scripts into pages"),
    "storage": (2, "extension-local storage"),
    "unlimitedStorage": (4, "unbounded local storage"),
    "alarms": (1, "timers"),
    "notifications": (2, "desktop notifications"),
    "contextMenus": (2, "context menu entries"),
    "identity": (8, "OAuth identity flow, Google account email access"),
    "downloads": (10, "can download files silently"),
    "clipboardRead": (18, "can read clipboard (passwords copied)"),
    "clipboardWrite": (4, "can write clipboard"),
    "geolocation": (12, "physical location"),
    "topSites": (6, "most-visited sites"),
    "webNavigation": (10, "observes all page navigations"),
    "browsingData": (15, "can wipe browsing data (cover tracks)"),
    "nativeMessaging": (25, "can talk to native host apps outside the browser"),
    "externally_connectable": (5, "web pages can message the extension"),
}

HOST_RISK = [
    ("<all_urls>", 25, "matches every URL incl. banking/crypto/email"),
    ("*://*/*", 25, "matches every http/https URL"),
    ("http://*/*", 15, "all plain-http traffic (no TLS)"),
]


def _host_points(pattern):
    for sig, pts, why in HOST_RISK:
        if pattern.strip() == sig:
            return pts, why
    return 0, ""


def analyze_manifest(manifest):
    findings = []   # (points, message)
    mv = manifest.get("manifest_version")
    if mv not in (2, 3):
        findings.append((10, f"unknown manifest_version={mv!r}"))
    perms = manifest.get("permissions", []) or []
    host_perms = manifest.get("host_permissions", []) or []
    # MV2 folds host patterns into "permissions"
    for p in perms:
        if isinstance(p, str) and ("://" in p or p == "<all_urls>"):
            host_perms.append(p)
    for p in perms:
        if p in PERM_RISK:
            pts, why = PERM_RISK[p]
            findings.append((pts, f'permission "{p}": {why}'))
    for hp in host_perms:
        pts, why = _host_points(hp)
        if pts:
            findings.append((pts, f'host permission "{hp}": {why}'))
    # content scripts
    for cs in manifest.get("content_scripts", []) or []:
        matches = cs.get("matches", [])
        for m in matches:
            pts, why = _host_points(m)
            if pts:
                findings.append((pts, f"content script matches \"{m}\": {why}"))
        if cs.get("all_frames"):
            findings.append((8, "content script runs in all_frames (iframes incl. login widgets)"))
        if cs.get("run_at") == "document_start":
            findings.append((5, "content script runs at document_start (before page JS)"))
    # background
    bg = manifest.get("background", {}) or {}
    if mv == 3 and "service_worker" in bg:
        findings.append((3, "MV3 background service worker"))
    if "page" in bg or "scripts" in bg:
        findings.append((8, "persistent background page (MV2 style, always running)"))
    # web accessible resources
    for war in manifest.get("web_accessible_resources", []) or []:
        res = war.get("resources", []) if isinstance(war, dict) else war
        matches = war.get("matches", []) if isinstance(war, dict) else []
        for m in matches:
            pts, why = _host_points(m)
            if pts:
                findings.append((pts, f"web-accessible resources exposed to \"{m}\": {why}"))
    # update_url: anything other than the Web Store = sideloaded/enterprise
    update_url = manifest.get("update_url", "")
    if update_url and "clients2.google.com" not in update_url \
            and "googleapis.com" not in update_url:
        findings.append((15, f'custom update_url "{update_url}" — not Web Store hosted (sideload risk)'))
    # externally connectable
    ec = manifest.get("externally_connectable", {}) or {}
    for m in ec.get("matches", []) or []:
        pts, why = _host_points(m)
        if pts:
            findings.append((pts, f"externally_connectable matches \"{m}\": {why}"))
    # CSP: remote script sources
    csp = manifest.get("content_security_policy", "")
    csp_text = json.dumps(csp)
    if re.search(r"https?://", csp_text):
        findings.append((20, "content_security_policy allows remote scripts (remote-code risk)"))
    if "unsafe-eval" in csp_text:
        findings.append((10, "CSP explicitly allows unsafe-eval"))
    # sandbox pages can run with reduced restrictions
    if manifest.get("sandbox", {}).get("pages"):
        findings.append((5, "sandboxed pages declared"))
    return {"manifest_version": mv, "findings": findings}

# ---------------------------------------------------------------------------
# 5. Static JS scan — looks for malicious *sinks*, not just permissions.
#    Permissions say what an extension *may* do; sinks show what it *does*.
# ---------------------------------------------------------------------------

# (regex, points, message)
JS_SINKS = [
    (r"chrome\.cookies\.(getAll|get|set|remove)", 25, "cookie API: reads/writes browser cookies"),
    (r"chrome\.history\.(search|getVisits)", 15, "reads browsing history"),
    (r"chrome\.bookmarks\.(getTree|getSubTree|search)", 10, "reads bookmarks"),
    (r"chrome\.tabs\.captureVisibleTab", 15, "screenshots the visible tab"),
    (r"chrome\.tabs\.executeScript", 15, "injects script into tabs (MV2)"),
    (r"chrome\.scripting\.executeScript", 12, "injects script into pages"),
    (r"chrome\.webRequest\.on\w+\.addListener", 15, "intercepts network requests"),
    (r"['\"]blocking['\"]", 10, "webRequest blocking mode (can alter traffic)"),
    (r"chrome\.debugger\.(attach|sendCommand)", 30, "attaches debugger to pages = total control"),
    (r"chrome\.proxy\.settings\.set", 25, "reroutes traffic through a proxy"),
    (r"chrome\.management\.(install|uninstall|setEnabled)", 20, "manages other extensions"),
    (r"chrome\.privacy\.", 12, "touches browser privacy settings"),
    (r"chrome\.browsingData\.remove", 15, "wipes browsing data (anti-forensics)"),
    (r"chrome\.downloads\.download", 10, "triggers silent downloads"),
    (r"chrome\.nativeMessaging|chrome\.runtime\.connectNative", 20, "talks to native host outside browser"),
    (r"document\.cookie", 12, "reads document.cookie (session theft in page context)"),
    (r"localStorage|sessionStorage", 6, "reads web storage (may hold tokens)"),
    (r"navigator\.clipboard\.readText", 15, "reads clipboard contents"),
    (r"addEventListener\s*\(\s*['\"](key(down|press|up)|input)['\"]", 25, "keylogging: captures keystrokes"),
    (r"\beval\s*\(", 15, "eval() — dynamic code execution"),
    (r"new\s+Function\s*\(", 15, "new Function() — dynamic code execution"),
    (r"setTimeout\s*\(\s*['\"]", 10, "setTimeout with string (implicit eval)"),
    (r"document\.write\s*\(", 8, "document.write (injection-prone)"),
    (r"\.innerHTML\s*=\s*.*location", 10, "innerHTML fed from URL (XSS-shaped)"),
    (r"WebSocket\s*\(", 8, "opens a WebSocket (C2-shaped channel)"),
    (r"chrome\.identity\.(getAuthToken|getProfileUserInfo)", 10, "grabs Google identity token/email"),
    (r"crypto\.subtle|SubtleCrypto", 4, "uses WebCrypto (note: also legit)"),
]

URL_RE = re.compile(r"""(?:"|')((?:https?|wss?)://[A-Za-z0-9.\-:]+(?:/[^\s"'<>]*)?)(?:"|')""")


def scan_js(code, filename, manifest_hosts):
    """Return list of (points, message) for one JS file."""
    out = []
    for pattern, pts, msg in JS_SINKS:
        for m in re.finditer(pattern, code):
            line = code.count("\n", 0, m.start()) + 1
            out.append((pts, f"{filename}:{line}: {msg}"))
    # Exfiltration-shaped URLs: remote fetch/XHR targets.
    for m in URL_RE.finditer(code):
        url = m.group(1)
        if re.search(r"\b(fetch|XMLHttpRequest|sendBeacon|\.src\s*=|\.href\s*=|open\s*\()", code[max(0, m.start() - 120):m.start()]):
            line = code.count("\n", 0, m.start()) + 1
            pts = 20 if not any(h in url for h in manifest_hosts) else 8
            out.append((pts, f"{filename}:{line}: sends data to {url}"))
    return out


def _manifest_hosts(manifest):
    hosts = set()
    for key in ("host_permissions",):
        for hp in manifest.get(key, []) or []:
            mm = re.search(r"://([^/]+)/", hp.replace("*", "x"))
            if mm:
                hosts.add(mm.group(1).replace("x", ""))
    for cs in manifest.get("content_scripts", []) or []:
        for m in cs.get("matches", []):
            mm = re.search(r"://([^/]+)/", m.replace("*", "x"))
            if mm:
                hosts.add(mm.group(1).replace("x", ""))
    return hosts

# ---------------------------------------------------------------------------
# 6. Triage engine.
# ---------------------------------------------------------------------------

VERDICTS = [(60, "MALICIOUS"), (25, "SUSPICIOUS"), (0, "CLEAN")]


def triage_extension(name_map, read_fn, label="extension"):
    """
    name_map: {zip_path_or_relpath: entry-or-None}; read_fn(name)->bytes.
    Works on a CRX payload or an unpacked directory.
    """
    findings = []
    if "manifest.json" not in name_map:
        return {"label": label, "verdict": "MALICIOUS", "score": 100,
                "findings": [(100, "no manifest.json at package root — not a valid extension")]}
    try:
        manifest = json.loads(read_fn("manifest.json").decode("utf-8"))
    except Exception as e:
        return {"label": label, "verdict": "MALICIOUS", "score": 100,
                "findings": [(100, f"manifest.json unreadable: {e}")]}
    man = analyze_manifest(manifest)
    findings += man["findings"]
    hosts = _manifest_hosts(manifest)
    for fname in name_map:
        if fname.endswith(".js"):
            try:
                code = read_fn(fname).decode("utf-8", "replace")
            except Exception:
                continue
            findings += scan_js(code, fname, hosts)
    # --- taint-lite refinement: a sink without an exfil destination in the
    # same file is usually benign (hotkeys, settings storage, cosmetic
    # filtering). Downgrade those; keep full weight only when the file also
    # ships data out. Manifest findings (permissions) are untouched.
    DOWNGRADEABLE = ("keylogging", "document.cookie", "web storage",
                     "clipboard", "eval()", "new Function()")
    by_file, manifest_only = {}, []
    for pts, msg in findings:
        m = re.match(r"([^:]+\.js):\d+: (.*)", msg)
        if m:
            by_file.setdefault(m.group(1), []).append((pts, m.group(2), msg))
        else:
            manifest_only.append((pts, msg))
    refined = list(manifest_only)
    for fname, items in by_file.items():
        has_exfil = any("sends data to" in text for _, text, _ in items)
        for pts, text, msg in items:
            if not has_exfil and any(k in text for k in DOWNGRADEABLE):
                pts = max(2, pts // 4)
                msg = msg + "  [no exfil in file — likely benign use]"
            refined.append((pts, msg))
    findings = refined
    # dedupe identical messages, keep max points
    best = {}
    for pts, msg in findings:
        base = re.sub(r":\d+:", ":", msg)
        if base not in best or pts > best[base][0]:
            best[base] = (pts, msg)
    findings = sorted(best.values(), reverse=True)
    score = min(100, sum(p for p, _ in findings))
    verdict = next(v for thresh, v in VERDICTS if score >= thresh)
    # Data theft needs a destination: with zero exfil sinks anywhere,
    # MALICIOUS is unwarranted no matter how broad the permissions are.
    any_exfil = any("sends data to" in msg for _, msg in findings)
    if verdict == "MALICIOUS" and not any_exfil:
        verdict = "SUSPICIOUS"
        findings.append((0, "no exfiltration destination found — broad "
                            "permissions alone do not convict; analyst review required"))
    return {"label": label, "verdict": verdict, "score": score,
            "manifest_version": man["manifest_version"], "findings": findings}


def report(result):
    lines = [f"=== {result['label']} ===",
             f"verdict: {result['verdict']}  (score {result['score']}/100)"]
    if result.get("manifest_version"):
        lines.append(f"manifest_version: {result['manifest_version']}")
    for pts, msg in result["findings"]:
        lines.append(f"  [+{pts:2d}] {msg}")
    if not result["findings"]:
        lines.append("  (no findings)")
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# 7. Chrome profile artifact: enumerate installed extensions from Preferences.
#    Preferences is JSON; per-extension data lives under
#    extensions.settings[<32-char id>]. Secure Preferences adds HMAC
#    protection (we just read, not verify).
# ---------------------------------------------------------------------------

def profile_extensions(prefs_path):
    with open(prefs_path, encoding="utf-8") as f:
        prefs = json.load(f)
    settings = prefs.get("extensions", {}).get("settings", {})
    out = []
    for ext_id, cfg in settings.items():
        manifest = cfg.get("manifest", {})
        out.append({
            "id": ext_id,
            "name": manifest.get("name", cfg.get("name", "?")),
            "version": manifest.get("version", "?"),
            "enabled": not cfg.get("disable_reasons"),
            "install_time": cfg.get("install_time", "?"),
            "from_webstore": cfg.get("from_webstore", False),
            "was_installed_by_default": cfg.get("was_installed_by_default", False),
        })
    return out


def main(argv):
    if len(argv) < 2:
        print("usage: crxray.py <file.crx | unpacked-dir | Preferences>")
        return 1
    target = argv[1]
    if os.path.isdir(target):
        name_map, read_fn = {}, None
        paths = {}
        for root, _dirs, files in os.walk(target):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, target).replace(os.sep, "/")
                paths[rel] = full
        result = triage_extension(paths, lambda n: open(paths[n], "rb").read(),
                                  label=target)
        print(report(result))
    elif target.endswith(".crx"):
        crx = parse_crx3(target)
        print(f"CRX3: id={crx['extension_id']} "
              f"crx_id_match={crx['crx_id_match']} "
              f"zip_offset={crx['zip_offset']} keys={len(crx['public_keys'])}")
        names = zip_name_map(crx["zip_bytes"])
        entries = {n: e for n, e in names.items()}
        result = triage_extension(entries,
                                  lambda n: zip_read(crx["zip_bytes"], entries[n]),
                                  label=target)
        print(report(result))
    elif os.path.basename(target).startswith("Preference"):
        for e in profile_extensions(target):
            print(f"{e['id']}  {e['name']} v{e['version']} "
                  f"enabled={e['enabled']} webstore={e['from_webstore']}")
    else:
        print("unknown target type"); return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
