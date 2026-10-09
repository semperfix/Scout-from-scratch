"""Certificate Transparency OSINT via crt.sh -- read-only.

Every publicly-trusted certificate is logged to CT logs; crt.sh exposes a
free JSON API over them. That makes CT a passive subdomain-enumeration
oracle: query %.example.com and you learn hostnames the target put on
certs -- dev boxes, staging, VPN portals -- without touching the target.
"""

import json
import urllib.request
import urllib.parse


def ct_search(domain: str, timeout=30):
    """Return raw crt.sh JSON entries for %.domain (read-only)."""
    q = urllib.parse.quote(f"%.{domain}", safe="%")
    url = f"https://crt.sh/?q={q}&output=json"
    req = urllib.request.Request(url, headers={"User-Agent": "cert-forensics-learning/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def subdomains(entries, domain: str):
    """Deduplicated lowercase subdomains of `domain` from CT entries."""
    subs = set()
    for e in entries:
        for name in e.get("name_value", "").split("\n"):
            name = name.strip().lower().rstrip(".")
            if name.startswith("*."):
                name = name[2:]
            if name.endswith("." + domain) or name == domain:
                subs.add(name)
    return sorted(subs)


def interesting(subs):
    """Heuristic: names that smell like infra worth a closer look."""
    keywords = ("dev", "test", "stage", "staging", "vpn", "admin", "portal",
                "internal", "intranet", "jenkins", "jira", "git", "mail",
                "owa", "exchange", "rdp", "ssh", "db", "backup", "old",
                "legacy", "beta", "demo", "api")
    return [s for s in subs if any(k in s.split(".")[0] for k in keywords)]
