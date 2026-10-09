"""QR triage: decode an image, classify the payload, flag quishing tells.

Quishing = phishing via QR code: the victim can't "hover to preview" the
URL the way they can with a link, so the QR hides the destination. This
module decodes locally (nothing uploaded anywhere) and scores the payload.
"""
from urllib.parse import urlparse

from qr_detect import detect, QRDetectError
from qr_codec import decode_matrix, QRError

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bitly.com", "cutt.ly", "rebrand.ly", "shorturl.at", "t.ly",
    "tiny.cc", "qrco.de",
}
RISKY_TLDS = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
              ".link", ".work", ".date", ".party", ".zip", ".mov"}


def classify(payload: bytes):
    """Return (kind, detail) for a decoded payload."""
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return "binary", f"{len(payload)} bytes, not UTF-8"
    t = text.strip()
    low = t.lower()
    if low.startswith(("http://", "https://")):
        return "url", t
    if low.startswith("wifi:"):
        return "wifi", t
    if low.startswith("mailto:"):
        return "mailto", t
    if low.startswith(("smsto:", "sms:")):
        return "sms", t
    if low.startswith("tel:"):
        return "tel", t
    if low.startswith("bitcoin:"):
        return "bitcoin", t
    if low.startswith("begin:vcard"):
        return "vcard", f"{len(t)} chars"
    if low.startswith("mecard:"):
        return "mecard", f"{len(t)} chars"
    if low.startswith("geo:"):
        return "geo", t
    return "text", t[:120]


def score_url(url):
    """Return a list of (severity, finding) for a URL payload."""
    findings = []
    try:
        p = urlparse(url)
    except Exception:
        return [("high", "URL does not parse")]
    host = (p.hostname or "").lower()

    if p.scheme == "http":
        findings.append(("medium", "plain HTTP (no TLS)"))
    if "@" in (p.netloc or ""):
        findings.append(("high", "credentials/redirect trick: '@' in authority"))
    if host.startswith("xn--") or ".xn--" in host:
        findings.append(("high", "punycode (IDN homograph) hostname"))
    # IP literal host
    h = host.strip("[]")
    if h.replace(".", "").isdigit() and h.count(".") == 3:
        findings.append(("high", "IP-literal host (no domain name)"))
    if host in SHORTENERS or any(host.endswith("." + s) for s in SHORTENERS):
        findings.append(("medium", "URL shortener hides the real destination"))
    if any(host.endswith(t) for t in RISKY_TLDS):
        findings.append(("medium", "high-abuse TLD"))
    if host.count(".") >= 4:
        findings.append(("low", "many subdomains (possible lookalike padding)"))
    if p.port:
        findings.append(("low", f"explicit port {p.port}"))
    if len(url) > 200 and ("?" in url or "&" in url):
        findings.append(("low", "long URL with query string"))
    return findings


_SEV_SCORE = {"low": 1, "medium": 3, "high": 6}


def triage_image(path):
    """Full pipeline on an image file -> report dict."""
    report = {"path": str(path), "ok": False}
    try:
        matrix, dinfo = detect(path)
    except QRDetectError as e:
        report["error"] = f"detection failed: {e}"
        return report
    try:
        payload, cinfo = decode_matrix(matrix)
    except QRError as e:
        report["error"] = f"decode failed: {e}"
        report["detect"] = dinfo
        return report
    kind, detail = classify(payload)
    findings = []
    if kind == "url":
        findings = score_url(detail)
    score = sum(_SEV_SCORE[s] for s, _ in findings)
    if score >= 6:
        verdict = "SUSPICIOUS"
    elif score >= 3:
        verdict = "WORTH-A-LOOK"
    else:
        verdict = "CLEAN"
    # error-correction margin: how much damage this code already absorbed
    corrected = cinfo["ec_corrected"]
    capacity = cinfo["ec_capacity"]
    report.update({
        "ok": True,
        "verdict": verdict,
        "kind": kind,
        "detail": detail,
        "findings": findings,
        "score": score,
        "version": cinfo["version"],
        "eclevel": cinfo["eclevel"],
        "mask": cinfo["mask"],
        "ec_corrected": corrected,
        "ec_capacity": capacity,
        "ec_margin": capacity - corrected,
        "detect": dinfo,
    })
    return report


def print_report(rep):
    if not rep.get("ok"):
        print(f"NO DECODE: {rep.get('error')}")
        return
    print(f"verdict: {rep['verdict']}  (score {rep['score']})")
    print(f"kind: {rep['kind']}  v{rep['version']}-{rep['eclevel']} mask {rep['mask']}")
    print(f"payload: {rep['detail'][:160]}")
    for sev, finding in rep["findings"]:
        print(f"  [{sev}] {finding}")
    print(f"error correction: absorbed {rep['ec_corrected']}/{rep['ec_capacity']} "
          f"(margin {rep['ec_margin']})")
