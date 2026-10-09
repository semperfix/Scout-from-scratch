"""URL feature engineering for phishing detection. Zero ML libraries.
Every feature is computed by hand from the URL's anatomy."""
import math
import re
from urllib.parse import urlparse, unquote

# Brands phishers love to impersonate (registrable domain, no TLD-specific tricks)
BRANDS = """google facebook amazon apple paypal microsoft netflix instagram
whatsapp bankofamerica chase wells fargo citi bank usbank capitalone americanexpress
discover ebay walmart target bestbuy costco home depot lowes fedex ups usps dhl
docusign dropbox icloud outlook office365 gmail yahoo aol linkedin twitter x tiktok
snapchat discord steam epicgames roblox minecraft coinbase binance kraken metamask
venmo cashapp zelle chime robinhood etrade fidelity schwab irs ssa dmv verizon
att tmobile sprint comcast spectrum xfinity tesla uber lyft doordash grubhub
airbnb booking expedia delta united americanairlines southwest marriott hilton
adobe salesforce zoom slack github gitlab bitbucket wordpress shopify stripe square
intuit turbotax hrblock geek squad best western appleid microsoftonline""".split()

# TLDs that show up disproportionately in phishing/malware feeds (abuse.ch, APWG)
RISKY_TLDS = {
    'top', 'xyz', 'click', 'link', 'work', 'gq', 'ml', 'tk', 'cf', 'buzz',
    'rest', 'fit', 'zip', 'mov', 'lol', 'sbs', 'quest', 'help', 'cn', 'ru',
    'su', 'biz', 'info', 'loan', 'win', 'date', 'party', 'stream', 'download',
    'men', 'okinawa', 'bid', 'cricket', 'webcam', 'trade', 'review', 'vip',
    'monster', 'bond', 'icu', 'cyou', 'sbs', 'tk', 'pw', 'cc',
}

# Words that scream "lure" when they appear in a URL
LURE_WORDS = {
    'login', 'signin', 'verify', 'verification', 'account', 'update', 'secure',
    'security', 'bank', 'banking', 'paypal', 'wallet', 'crypto', 'bitcoin',
    'free', 'prize', 'winner', 'bonus', 'claim', 'reward', 'gift', 'urgent',
    'suspended', 'locked', 'confirm', 'password', 'credential', 'invoice',
    'payment', 'refund', 'limited', 'offer', 'deal', 'promo', 'support',
    'service', 'alert', 'notice', 'ebay', 'appleid',
}

RISKY_EXTENSIONS = {'.exe', '.scr', '.bat', '.cmd', '.msi', '.jar', '.vbs',
                    '.ps1', '.apk', '.dmg', '.zip', '.rar', '.iso'}

IPV4_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
HEXESC_RE = re.compile(r'%[0-9a-fA-F]{2}')


def damerau_levenshtein(a, b, max_dist=None):
    """True Damerau-Levenshtein (adjacent transpositions) from scratch.

    max_dist: optional cutoff — returns max_dist+1 early when the true
    distance provably exceeds it (row-minimum banding). Exact for
    distances <= max_dist.
    """
    if max_dist is not None and abs(len(a) - len(b)) > max_dist:
        return max_dist + 1
    da = {}
    d = [[0] * (len(b) + 2) for _ in range(len(a) + 2)]
    maxdist = len(a) + len(b)
    d[0][0] = maxdist
    for i in range(len(a) + 1):
        d[i + 1][0] = maxdist
        d[i + 1][1] = i
    for j in range(len(b) + 1):
        d[0][j + 1] = maxdist
        d[1][j + 1] = j
    for i in range(1, len(a) + 1):
        db = 0
        row_min = maxdist
        for j in range(1, len(b) + 1):
            i1 = da.get(b[j - 1], 0)
            j1 = db
            cost = 0 if a[i - 1] == b[j - 1] else 1
            if cost == 0:
                db = j
            v = min(
                d[i][j] + cost,          # substitution
                d[i + 1][j] + 1,        # insertion
                d[i][j + 1] + 1,        # deletion
                d[i1][j1] + (i - i1 - 1) + 1 + (j - j1 - 1),  # transposition
            )
            d[i + 1][j + 1] = v
            if v < row_min:
                row_min = v
        da[a[i - 1]] = i
        if max_dist is not None and row_min > max_dist:
            return max_dist + 1
    return d[len(a) + 1][len(b) + 1]


def shannon_entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def registrable_domain(host):
    """Poor man's eTLD+1: last two labels. Good enough for feature work."""
    labels = host.split('.')
    return '.'.join(labels[-2:]) if len(labels) >= 2 else host


def typosquat_features(host):
    """Distance from the host's labels to known brands. Returns
    (min_distance, closest_brand, exact_brand_subdomain_flag)."""
    labels = host.lower().split('.')
    reg = registrable_domain(host.lower())
    best, best_brand = 99, None
    # split hyphenated compounds too: 'paypa1-login' hides 'paypa1'
    pieces = []
    for lab in labels:
        pieces.append(lab)
        if '-' in lab or '_' in lab:
            pieces.extend(p for p in re.split(r'[-_]', lab) if p)
    for lab in pieces:
        if len(lab) < 3 or lab.isdigit():
            continue
        for brand in BRANDS:
            # DL(a,b) >= |len(a)-len(b)| : skip pairs that can't beat best
            if abs(len(lab) - len(brand)) > best:
                continue
            dd = damerau_levenshtein(lab, brand, max_dist=min(best, 5))
            if dd < best:
                best, best_brand = dd, brand
                if best == 0:
                    break
        if best == 0:
            break
    if best_brand is None:
        best, best_brand = 6, BRANDS[0]
    # brand-as-subdomain trick: paypal.evil.com
    brand_sub = 0
    if len(labels) > 2:
        for lab in labels[:-2]:
            if lab in BRANDS and registrable_domain(host.lower()) not in \
                    {b + '.' + t for b in BRANDS for t in ('com',)}:
                brand_sub = 1
                break
    return min(best, 6), best_brand, brand_sub


FEATURE_NAMES = [
    'url_len', 'host_len', 'path_len', 'query_len',
    'host_dots', 'host_hyphens', 'host_digits', 'host_digit_ratio',
    'longest_label', 'subdomain_depth', 'host_entropy', 'path_entropy',
    'is_ip', 'has_port', 'nonstd_port', 'has_at', 'hex_escapes',
    'double_slash_path', 'punycode', 'non_ascii_host',
    'tld_len', 'risky_tld', 'lure_words', 'path_segments',
    'risky_ext', 'query_params', 'is_https', 'typo_dist',
    'brand_subdomain', 'userinfo_present',
]


def extract_features(url):
    """Return a dict of numeric features for one URL."""
    url = url.strip()
    if '://' not in url:
        url = 'http://' + url
    p = urlparse(url)
    host = (p.hostname or '').lower()
    path = p.path or ''
    query = p.query or ''
    labels = host.split('.') if host else []
    reg = registrable_domain(host)
    tld = labels[-1] if labels else ''

    is_ip = 1 if IPV4_RE.match(host) or (host.startswith('[') and host.endswith(']')) else 0
    port = None
    try:
        port = p.port
    except ValueError:
        port = -1
    scheme = p.scheme.lower()

    typo_dist, _brand, brand_sub = typosquat_features(host)
    lowered = url.lower()
    lure = sum(1 for w in LURE_WORDS if w in lowered)
    path_low = path.lower()
    risky_ext = 1 if any(path_low.endswith(e) for e in RISKY_EXTENSIONS) else 0

    feats = {
        'url_len': len(url),
        'host_len': len(host),
        'path_len': len(path),
        'query_len': len(query),
        'host_dots': host.count('.'),
        'host_hyphens': host.count('-'),
        'host_digits': sum(c.isdigit() for c in host),
        'host_digit_ratio': sum(c.isdigit() for c in host) / max(len(host), 1),
        'longest_label': max((len(l) for l in labels), default=0),
        'subdomain_depth': max(len(labels) - 2, 0),
        'host_entropy': shannon_entropy(host),
        'path_entropy': shannon_entropy(path),
        'is_ip': is_ip,
        'has_port': 1 if port else 0,
        'nonstd_port': 1 if port and port not in (80, 443) else 0,
        'has_at': 1 if '@' in url else 0,
        'hex_escapes': len(HEXESC_RE.findall(url)),
        'double_slash_path': 1 if '//' in path else 0,
        'punycode': 1 if 'xn--' in host else 0,
        'non_ascii_host': 1 if any(ord(c) > 127 for c in host) else 0,
        'tld_len': len(tld),
        'risky_tld': 1 if tld in RISKY_TLDS else 0,
        'lure_words': lure,
        'path_segments': len([s for s in path.split('/') if s]),
        'risky_ext': risky_ext,
        'query_params': query.count('&') + (1 if query else 0),
        'is_https': 1 if scheme == 'https' else 0,
        'typo_dist': typo_dist,
        'brand_subdomain': brand_sub,
        'userinfo_present': 1 if p.username else 0,
    }
    return feats


def featurize(urls):
    """urls -> (n, d) float matrix in FEATURE_NAMES order."""
    import numpy as np
    rows = []
    for u in urls:
        f = extract_features(u)
        rows.append([float(f[name]) for name in FEATURE_NAMES])
    return np.array(rows, dtype=float)
