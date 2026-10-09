"""Dataset builders from real public feeds (read-only downloads).

- Malicious URLs: abuse.ch URLhaus recent CSV (label 1)
- Benign URLs:    Tranco top list, http://<domain> (label 0)
- Messages:       UCI SMS Spam Collection (ham 0 / spam 1)
"""
import csv
import zipfile
from features import featurize


def load_urlhaus(path='urlhaus.csv'):
    urls = []
    with open(path, newline='', encoding='utf-8', errors='replace') as f:
        rows = [l for l in f if not l.startswith('#') and l.strip()]
    reader = csv.reader(rows)
    for r in reader:
        if len(r) >= 3 and r[2].startswith('http'):
            urls.append(r[2].strip())
    # dedupe, keep order
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def load_tranco(path='tranco.zip', n=60000):
    domains = []
    with zipfile.ZipFile(path) as z:
        name = z.namelist()[0]
        with z.open(name) as f:
            for i, line in enumerate(f):
                if i >= n:
                    break
                parts = line.decode('ascii', 'replace').strip().split(',')
                if len(parts) == 2 and parts[1]:
                    domains.append('http://' + parts[1].strip().lower())
    return domains


def _typo_variants(brand, rng):
    """One-edit typos of a brand name: lookalike substitution, deletion,
    adjacent transposition, duplication, hyphen split."""
    lookalikes = {'o': '0', 'l': '1', 'i': '1', 'e': '3', 'a': '4',
                  's': '5', 't': '7', 'b': '8', 'g': '9'}
    v = set()
    b = brand
    for i, ch in enumerate(b):
        if ch in lookalikes:
            v.add(b[:i] + lookalikes[ch] + b[i + 1:])   # substitut1on
        v.add(b[:i] + b[i + 1:])                          # deletion
        v.add(b[:i] + ch + b[i:])                         # duplication
        if i > 0:
            v.add(b[:i - 1] + b[i] + b[i - 1] + b[i + 1:])  # transposition
            v.add(b[:i] + '-' + b[i:])                   # hyphen split
    v.discard(b)
    return sorted(v)


def synthetic_brand_phish(n=4000, seed=1234):
    """SYNTHETIC brand-impersonation phish URLs (labeled malicious).

    Why synthetic rows exist: abuse.ch URLhaus 'recent' skews heavily to
    malware-download URLs (bare IP:port hosts, /i paths). Brand-impersonation
    phish — typosquatted domains, lure words, brand-as-subdomain — the shape
    that actually arrives in texts/QRs, is underrepresented, so a model
    trained on URLhaus alone never learns the typosquat/lure features
    (measured: their weights came out ~0). These rows are synthetic BY
    CONSTRUCTION and are documented as such; adversarial evaluation uses
    disjoint hand-written URLs, never this generator's outputs.
    """
    from features import BRANDS, RISKY_TLDS
    rng = __import__('numpy').random.default_rng(seed)
    brands = [b for b in
              ['paypal', 'apple', 'amazon', 'microsoft', 'netflix', 'chase',
               'bankofamerica', 'wellsfargo', 'docusign', 'coinbase',
               'instagram', 'facebook', 'dhl', 'fedex', 'usps']
              if b in BRANDS]
    evil = ['secure', 'login', 'verify', 'support', 'account', 'update',
            'service', 'help', 'online', 'web', 'portal', 'id']
    lures = ['signin', 'login', 'verify-account', 'update-payment', 'secure',
             'account-suspended', 'confirm-identity', 'unlock-account',
             'billing-update', 'security-check']
    tlds = sorted(RISKY_TLDS)[:14] + ['com', 'net', 'org']
    out = []
    while len(out) < n:
        brand = brands[rng.integers(len(brands))]
        typo = rng.choice(_typo_variants(brand, rng))
        tld = rng.choice(tlds)
        lure = rng.choice(lures)
        shape = rng.integers(4)
        if shape == 0:
            host = f'{typo}.{tld}'
        elif shape == 1:
            host = f'{typo}-{rng.choice(evil)}.{tld}'
        elif shape == 2:
            host = f'{brand}.{rng.choice(evil)}-{rng.choice(evil)}.{tld}'
        else:
            host = f'{rng.choice(evil)}-{brand}.{tld}'
        scheme = 'https' if rng.random() < 0.7 else 'http'
        out.append(f'{scheme}://{host}/{lure}')
    return out


def build_url_dataset(n_benign=30000, n_synth=4000, seed=0):
    """Balanced (malicious, benign) URL dataset -> (urls, y)."""
    import numpy as np
    rng = np.random.default_rng(seed)
    mal = load_urlhaus()
    ben = load_tranco()
    syn = synthetic_brand_phish(n_synth, seed=seed + 1)
    n_mal = min(len(mal), n_benign - n_synth)
    mal = list(rng.choice(mal, n_mal, replace=False))
    ben = list(rng.choice(ben, n_benign, replace=False))
    urls = mal + syn + ben
    y = np.array([1] * (len(mal) + len(syn)) + [0] * len(ben))
    # De-leak: benign entries are bare "http://domain" while malicious URLs
    # carry their real scheme (~50/50 http/https in URLhaus). A model would
    # otherwise learn "https => malicious" from the construction, not the
    # world. Randomize benign schemes to match the malicious distribution.
    # Known residual bias (documented in README): benign rows are domain
    # homepages with no path, so path-shape features are inflated on the
    # malicious side. Treat scores as one signal, not a verdict.
    n_mal_total = len(mal) + len(syn)
    ben_https = rng.random(len(ben)) < 0.503
    urls = [u.replace('http://', 'https://', 1) if (i >= n_mal_total and https)
            else u
            for i, (u, https) in enumerate(
                zip(urls, [False] * n_mal_total + list(ben_https)))]
    idx = rng.permutation(len(urls))
    return [urls[i] for i in idx], y[idx]


def load_sms(path='smsdata/SMSSpamCollection'):
    texts, labels = [], []
    with open(path, encoding='utf-8', errors='replace') as f:
        for line in f:
            line = line.rstrip('\n')
            if not line.strip():
                continue
            lab, _, txt = line.partition('\t')
            labels.append(1 if lab.strip() == 'spam' else 0)
            texts.append(txt)
    import numpy as np
    return texts, np.array(labels)


if __name__ == '__main__':
    urls, y = build_url_dataset()
    print(f'urls: {len(urls)}  malicious={int(y.sum())} benign={int((1-y).sum())}')
    X = featurize(urls[:5])
    print('feature matrix sample shape:', X.shape)
    texts, ys = load_sms()
    print(f'sms: {len(texts)} spam={int(ys.sum())} ham={int((1-ys).sum())}')
