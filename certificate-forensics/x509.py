"""X.509 certificate structure parser, from scratch. Zero dependencies.

Parses RFC 5280 Certificate ::= SEQUENCE { tbsCertificate,
signatureAlgorithm, signatureValue } into plain Python dicts: version,
serial, issuer/subject DNs, validity window, SubjectPublicKeyInfo
(RSA / EC / Ed25519), and the standard extensions (SKI, AKI, KeyUsage,
SAN, BasicConstraints, EKU, CRLDistributionPoints, AIA, policies).

No validation here -- that lives in verify.py. This module only answers
"what does this certificate say about itself".
"""

from der import (
    Node, parse_der, pem_to_der, DERError,
    TAG_SEQUENCE, TAG_SET, TAG_INTEGER, TAG_BIT_STRING, TAG_OCTET_STRING,
    TAG_OID, TAG_NULL, TAG_BOOLEAN, TAG_UTCTIME, TAG_GENERALIZEDTIME,
    CLASS_CONTEXT, decode_oid,
)

# -- OID tables ----------------------------------------------------------

SIG_ALGS = {
    "1.2.840.113549.1.1.2": ("md2WithRSAEncryption", "md2", "rsa"),
    "1.2.840.113549.1.1.4": ("md5WithRSAEncryption", "md5", "rsa"),
    "1.2.840.113549.1.1.5": ("sha1WithRSAEncryption", "sha1", "rsa"),
    "1.2.840.113549.1.1.11": ("sha256WithRSAEncryption", "sha256", "rsa"),
    "1.2.840.113549.1.1.12": ("sha384WithRSAEncryption", "sha384", "rsa"),
    "1.2.840.113549.1.1.13": ("sha512WithRSAEncryption", "sha512", "rsa"),
    "1.2.840.113549.1.1.14": ("sha224WithRSAEncryption", "sha224", "rsa"),
    "1.2.840.113549.1.1.10": ("rsassaPss", None, "rsa-pss"),
    "1.2.840.10045.4.1": ("ecdsa-with-SHA1", "sha1", "ecdsa"),
    "1.2.840.10045.4.3.1": ("ecdsa-with-SHA224", "sha224", "ecdsa"),
    "1.2.840.10045.4.3.2": ("ecdsa-with-SHA256", "sha256", "ecdsa"),
    "1.2.840.10045.4.3.3": ("ecdsa-with-SHA384", "sha384", "ecdsa"),
    "1.2.840.10045.4.3.4": ("ecdsa-with-SHA512", "sha512", "ecdsa"),
    "1.3.101.112": ("Ed25519", "ed25519", "ed25519"),
    "1.3.101.113": ("Ed448", "ed448", "ed448"),
    "1.2.840.10040.4.3": ("dsa-with-SHA1", "sha1", "dsa"),
}

KEY_ALGS = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.3.101.110": "X25519",
    "1.3.101.111": "X448",
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.10040.4.1": "dsa",
}

NAMED_CURVES = {
    "1.2.840.10045.3.1.7": "secp256r1",   # P-256
    "1.3.132.0.34": "secp384r1",          # P-384
    "1.3.132.0.35": "secp521r1",          # P-521
    "1.3.132.0.10": "secp256k1",
}

DN_ATTRS = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber",
    "2.5.4.4": "SN", "2.5.4.42": "GN",
    "1.2.840.113549.1.9.1": "emailAddress",
    "2.5.4.12": "title", "2.5.4.13": "description",
    "0.9.2342.19200300.100.1.25": "DC",
}

EXT_NAMES = {
    "2.5.29.14": "subjectKeyIdentifier",
    "2.5.29.15": "keyUsage",
    "2.5.29.16": "privateKeyUsagePeriod",
    "2.5.29.17": "subjectAltName",
    "2.5.29.18": "issuerAltName",
    "2.5.29.19": "basicConstraints",
    "2.5.29.30": "nameConstraints",
    "2.5.29.31": "cRLDistributionPoints",
    "2.5.29.32": "certificatePolicies",
    "2.5.29.35": "authorityKeyIdentifier",
    "2.5.29.37": "extKeyUsage",
    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "2.5.29.54": "inhibitAnyPolicy",
}

KEY_USAGES = ["digitalSignature", "nonRepudiation", "keyEncipherment",
              "dataEncipherment", "keyAgreement", "keyCertSign",
              "cRLSign", "encipherOnly", "decipherOnly"]

EKU_OIDS = {
    "1.3.6.1.5.5.7.3.1": "serverAuth",
    "1.3.6.1.5.5.7.3.2": "clientAuth",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
    "1.3.6.1.5.5.7.3.8": "timeStamping",
    "1.3.6.1.5.5.7.3.9": "OCSPSigning",
    "2.5.29.37.0": "anyExtendedKeyUsage",
}


# -- Name (DN) -----------------------------------------------------------

def parse_name(node: Node):
    """RDNSequence -> list of (short_name, value) in order, plus raw DER."""
    rdns = []
    for rdn_set in node.children:          # each RDN is a SET
        for atv in rdn_set.children:       # AttributeTypeAndValue
            oid = atv.child(0).as_oid()
            val_node = atv.child(1)
            try:
                val = val_node.as_str()
            except DERError:
                val = val_node.value.hex()
            rdns.append((DN_ATTRS.get(oid, oid), val))
    return rdns


def dn_string(rdns) -> str:
    return ", ".join(f"{k}={v}" for k, v in reversed(rdns))


# -- SubjectPublicKeyInfo ------------------------------------------------

def parse_spki(node: Node):
    alg_id = node.child(0)
    alg_oid = alg_id.child(0).as_oid()
    params = alg_id.child(1) if len(alg_id) > 1 else None
    unused, key_bytes = node.child(1).bitstring()
    if unused != 0:
        raise DERError("SPKI BIT STRING has unused bits")
    info = {"alg_oid": alg_oid,
            "alg_name": KEY_ALGS.get(alg_oid, alg_oid),
            "params": params, "key_bytes": key_bytes}
    if alg_oid == "1.2.840.113549.1.1.1":          # RSA
        rk = parse_der(key_bytes)
        info["n"] = rk.child(0).as_int()
        info["e"] = rk.child(1).as_int()
        info["bits"] = info["n"].bit_length()
    elif alg_oid == "1.2.840.10045.2.1":           # EC
        curve_oid = params.as_oid() if params is not None else None
        info["curve_oid"] = curve_oid
        info["curve"] = NAMED_CURVES.get(curve_oid, curve_oid)
        if key_bytes[0] != 0x04:
            raise DERError("only uncompressed EC points supported")
        size = (len(key_bytes) - 1) // 2
        info["x"] = int.from_bytes(key_bytes[1:1 + size], "big")
        info["y"] = int.from_bytes(key_bytes[1 + size:], "big")
        info["bits"] = size * 8
    elif alg_oid in ("1.3.101.112", "1.3.101.113"):  # Ed25519/Ed448
        info["bits"] = len(key_bytes) * 8
    return info


# -- extensions ----------------------------------------------------------

def _general_names(node: Node):
    """GeneralNames -> list of (type, value)."""
    out = []
    for gn in node.children:
        t = gn.tag
        if t == 1:   # rfc822Name
            out.append(("email", gn.value.decode("ascii", "replace")))
        elif t == 2:  # dNSName
            out.append(("dns", gn.value.decode("ascii", "replace")))
        elif t == 6:  # uniformResourceIdentifier
            out.append(("uri", gn.value.decode("ascii", "replace")))
        elif t == 7:  # iPAddress
            out.append(("ip", ".".join(str(b) for b in gn.value)
                        if len(gn.value) == 4 else gn.value.hex()))
        else:
            out.append((f"gn-{t}", gn.value.hex()))
    return out


def parse_extension(ext: Node):
    oid = ext.child(0).as_oid()
    if len(ext) == 3:
        critical = ext.child(1).as_bool()
        raw = ext.child(2).as_bytes()
    else:
        critical = False
        raw = ext.child(1).as_bytes()
    val = parse_der(raw)
    name = EXT_NAMES.get(oid, oid)
    parsed = None
    try:
        if oid == "2.5.29.19":  # BasicConstraints
            ca = val.child(0).as_bool() if len(val) > 0 else False
            pathlen = val.child(1).as_int() if len(val) > 1 else None
            parsed = {"ca": ca, "pathlen": pathlen}
        elif oid == "2.5.29.15":  # KeyUsage
            # BIT STRING: bit 0 (MSB of first octet) = digitalSignature, etc.
            ub, kb = val.bitstring()
            nbits = len(kb) * 8 - ub
            raw = int.from_bytes(kb, "big") >> ub
            names = [KEY_USAGES[i] for i in range(min(nbits, 9))
                     if (raw >> (nbits - 1 - i)) & 1]
            parsed = {"bits": raw, "names": names}
        elif oid in ("2.5.29.17", "2.5.29.18"):  # SAN / IAN
            parsed = _general_names(val)
        elif oid == "2.5.29.14":  # SKI
            parsed = val.as_bytes().hex()
        elif oid == "2.5.29.35":  # AKI
            # AuthorityKeyIdentifier ::= SEQUENCE {
            #   keyIdentifier [0] KeyIdentifier OPTIONAL,  (OCTET STRING bytes)
            #   authorityCertIssuer [1] GeneralNames OPTIONAL,
            #   authorityCertSerialNumber [2] INTEGER OPTIONAL }
            d = {}
            for f in val.children:
                if f.tag == 0 and f.cls == CLASS_CONTEXT:
                    d["keyid"] = f.value.hex()
                elif f.tag == 1 and f.cls == CLASS_CONTEXT:
                    d["issuer"] = _general_names(f.children[0])
                elif f.tag == 2 and f.cls == CLASS_CONTEXT:
                    # INTEGER content bytes, two's complement
                    v = int.from_bytes(f.value, "big")
                    if f.value and f.value[0] & 0x80:
                        v -= 1 << (8 * len(f.value))
                    d["serial"] = v
            parsed = d
        elif oid == "2.5.29.37":  # EKU
            parsed = [EKU_OIDS.get(c.as_oid(), c.as_oid()) for c in val.children]
        elif oid == "2.5.29.31":  # CRLDistributionPoints
            urls = []
            for dp in val.children:
                for f in dp.children:
                    if f.tag == 0 and f.cls == CLASS_CONTEXT and f.constructed:
                        for gn in f.children[0].children:
                            if gn.tag == 6:
                                urls.append(gn.value.decode("ascii", "replace"))
            parsed = urls
        elif oid == "1.3.6.1.5.5.7.1.1":  # AIA
            d = {}
            for ad in val.children:
                method = ad.child(0).as_oid()
                loc = ad.child(1)
                v = loc.value.decode("ascii", "replace") if loc.tag == 6 else loc.value.hex()
                d.setdefault({"1.3.6.1.5.5.7.48.1": "ocsp",
                              "1.3.6.1.5.5.7.48.2": "caIssuers"}.get(method, method),
                             []).append(v)
            parsed = d
    except (DERError, IndexError, ValueError):
        parsed = None
    return {"oid": oid, "name": name, "critical": critical,
            "raw": raw, "parsed": parsed}


# -- top level -----------------------------------------------------------

def parse_cert(der_bytes: bytes) -> dict:
    """Parse a DER certificate; also slices out exact tbsCertificate bytes."""
    # Manual top-level walk so we can slice the exact tbsCertificate encoding
    # (needed for signature verification -- must be byte-identical).
    from der import _parse_tlv
    top, off0 = _parse_tlv(der_bytes, 0)
    if off0 != len(der_bytes):
        raise DERError("trailing garbage after Certificate")
    if top.tag != TAG_SEQUENCE or len(top) != 3:
        raise DERError("not a Certificate SEQUENCE")
    tbs, sig_alg_node, sig_val_node = top.children
    tbs_der = der_bytes[top.header_len:top.header_len + tbs.header_len + len(tbs.value)]
    if tbs.tag != TAG_SEQUENCE:
        raise DERError("tbsCertificate not a SEQUENCE")

    kids = list(tbs.children)
    # [0] EXPLICIT version
    if kids[0].cls == CLASS_CONTEXT and kids[0].tag == 0:
        version = kids[0].child(0).as_int() + 1
        kids = kids[1:]
    else:
        version = 1
    serial = kids[0].as_int()
    sig_alg_oid = kids[1].child(0).as_oid()
    issuer = parse_name(kids[2])
    validity = kids[3]
    not_before = validity.child(0).as_time()
    not_after = validity.child(1).as_time()
    subject = parse_name(kids[4])
    spki = parse_spki(kids[5])
    extensions = {}
    for k in kids[6:]:
        if k.cls == CLASS_CONTEXT and k.tag == 3:  # [3] EXPLICIT extensions
            for ext in k.child(0).children:
                e = parse_extension(ext)
                extensions[e["name"]] = e
    # tbs bytes for signature verification -- exact slice, byte-identical.
    sig_name, digest, sigtype = SIG_ALGS.get(sig_alg_oid, (sig_alg_oid, None, None))
    unused, sig_bytes = sig_val_node.bitstring()

    return {
        "der": der_bytes,
        "tbs_der": tbs_der,
        "version": version,
        "serial": serial,
        "serial_hex": format(serial, "x"),
        "sig_alg_oid": sig_alg_oid,
        "sig_alg": sig_name,
        "sig_digest": digest,
        "sig_type": sigtype,
        "issuer": issuer,
        "issuer_str": dn_string(issuer),
        "subject": subject,
        "subject_str": dn_string(subject),
        "not_before": not_before,
        "not_after": not_after,
        "spki": spki,
        "extensions": extensions,
        "signature": sig_bytes,
        "sig_unused_bits": unused,
    }


def load_pem_file(path: str, skip_bad: bool = False) -> list[dict]:
    """Load all certs from a PEM bundle. With skip_bad=True, unparseable
    blocks (e.g. the truncated entries some system bundles ship) are
    skipped instead of aborting the whole load."""
    from der import split_pems
    with open(path) as f:
        text = f.read()
    certs = []
    skipped = 0
    for b in split_pems(text):
        try:
            certs.append(parse_cert(pem_to_der(b)))
        except DERError:
            if not skip_bad:
                raise
            skipped += 1
    if skipped:
        import sys
        print(f"note: skipped {skipped} unparseable PEM block(s) in {path}",
              file=sys.stderr)
    return certs
