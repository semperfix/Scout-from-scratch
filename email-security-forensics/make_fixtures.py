#!/usr/bin/env python3
"""Generate test fixtures: a DKIM-signed email, a tampered copy, an unsigned
mail, and the stub-DNS JSON that emailauth.py needs to verify them.

Regenerates the RSA key each run (1024-bit; a few seconds at most).
Writes into fixtures/.
"""
import json
import os

from dkim import generate_rsa_key, dkim_dns_txt, sign_raw_email

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
os.makedirs(FIX, exist_ok=True)

BASE = (b"From: alice@example.com\r\n"
        b"To: bob@example.org\r\n"
        b"Subject: lunch tomorrow?\r\n"
        b"Date: Thu, 08 Oct 2026 12:00:00 -0400\r\n"
        b"Message-ID: <20261008.1@example.com>\r\n"
        b"\r\n"
        b"Hi Bob,\r\n"
        b"\r\n"
        b"Are we still on for lunch tomorrow at noon?\r\n"
        b"\r\n"
        b"-- Alice\r\n")

SENDER_IP = "192.0.2.44"  # inside the SPF ip4:192.0.2.0/24 range


def main():
    n, e, d = generate_rsa_key(bits=1024)
    print(f"generated RSA key: n is {n.bit_length()} bits")

    signed = sign_raw_email(BASE, "example.com", "sel1", (n, e, d))
    with open(os.path.join(FIX, "signed.eml"), "wb") as f:
        f.write(signed)

    tampered = signed.replace(b"tomorrow at noon?", b"tomorrow at midnight?")
    with open(os.path.join(FIX, "tampered.eml"), "wb") as f:
        f.write(tampered)

    with open(os.path.join(FIX, "unsigned.eml"), "wb") as f:
        f.write(BASE)

    stub = {
        "txt": {
            "example.com": "v=spf1 ip4:192.0.2.0/24 -all",
            "sel1._domainkey.example.com": dkim_dns_txt(n, e),
            "_dmarc.example.com": "v=DMARC1; p=reject; adkim=r; aspf=r;",
        },
        "a": {"example.com": ["192.0.2.10"]},
        "mx": {"example.com": ["mail.example.com"]},
        "_note": f"sender IP for fixtures: {SENDER_IP} (SPF pass); "
                 "try 203.0.113.9 for SPF fail",
    }
    with open(os.path.join(FIX, "dns-stub.json"), "w") as f:
        json.dump(stub, f, indent=2)
    print("wrote fixtures/signed.eml, tampered.eml, unsigned.eml, dns-stub.json")


if __name__ == "__main__":
    main()
