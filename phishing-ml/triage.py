"""phishcheck: explainable phishing triage for one URL or one message.

Usage:
    python3 triage.py url  <url>
    python3 triage.py text "<message>"

Trains (or loads cached) models on the real feeds, then scores the input
and prints the top contributing features — no black box.
"""
import json
import os
import sys

import numpy as np

from data import build_url_dataset, load_sms
from features import (FEATURE_NAMES, extract_features, featurize,
                      typosquat_features, damerau_levenshtein, LURE_WORDS)
from ml import (Standardizer, LogisticRegression, MultinomialNB,
                CountVectorizer, prf, roc_auc)

CACHE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models.json')

VERDICTS = [(0.85, 'MALICIOUS'), (0.60, 'SUSPICIOUS'),
            (0.35, 'WORTH-A-LOOK'), (0.0, 'CLEAN')]


def train_url_model():
    urls, y = build_url_dataset()
    X = featurize(urls)
    std = Standardizer().fit(X)
    Xs = std.transform(X)
    clf = LogisticRegression(lr=0.5, l2=1.0, max_iter=2000).fit(Xs, y)
    return {'std_mean': std.mean_.tolist(), 'std_scale': std.scale_.tolist(),
            'coef': clf.coef_.tolist(), 'names': FEATURE_NAMES}


def train_text_model():
    texts, y = load_sms()
    vec = CountVectorizer(min_df=3).fit(texts)
    X = vec.transform(texts)
    clf = MultinomialNB(alpha=1.0).fit(X, y)
    return {'vocab': vec.vocab_,
            'log_prob': {str(c): clf.log_prob_[c].tolist()
                         for c in clf.classes_},
            'log_prior': {str(c): clf.log_prior_[c] for c in clf.classes_},
            'classes': [int(c) for c in clf.classes_]}


def get_models():
    if os.path.exists(CACHE):
        with open(CACHE) as f:
            return json.load(f)
    m = {'url': train_url_model(), 'text': train_text_model()}
    with open(CACHE, 'w') as f:
        json.dump(m, f)
    return m


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def score_url(url, m):
    um = m['url']
    feats = extract_features(url)
    x = np.array([[float(feats[n]) for n in um['names']]])
    xs = (x - np.array(um['std_mean'])) / np.array(um['std_scale'])
    w = np.array(um['coef'])
    z = float((np.column_stack([np.ones(1), xs]) @ w)[0])
    p = float(sigmoid(z))
    # per-feature contribution to the log-odds (bias excluded)
    contrib = sorted(
        [((um['names'][i], float(w[i + 1] * xs[0, i])))
         for i in range(len(um['names']))],
        key=lambda t: -abs(t[1]))[:8]
    # Rule layer: deterministic hard flags. These are NOT learned — they are
    # explicit analyst rules for shapes the model underweights, listed
    # verbatim in the output so the verdict stays explainable.
    flags = []
    host = url.split('/')[2] if '://' in url else url.split('/')[0]
    td, brand, bsub = typosquat_features(host.split(':')[0].lower())
    lures = sorted({wd for wd in LURE_WORDS if wd in url.lower()})
    if feats['userinfo_present']:
        flags.append(('CREDENTIALS-IN-URL (user:pass@host)', 0.85))
    if td <= 1 and (lures or feats['risky_tld']):
        flags.append((f'TYPOSQUAT: "{brand}" at distance {td} + lure/risky-TLD', 0.80))
    if bsub and lures:
        flags.append(('BRAND-AS-SUBDOMAIN + lure words', 0.75))
    if feats['punycode'] and lures:
        flags.append(('PUNYCODE host + lure words', 0.70))
    if feats['is_ip'] and feats['nonstd_port']:
        flags.append(('IP-LITERAL host + nonstandard port', 0.70))
    if flags:
        p = max(p, max(f[1] for f in flags))
    return p, feats, contrib, flags, (td, brand, bsub), lures


def score_text(text, m):
    tm = m['text']
    vocab = tm['vocab']
    toks = [t for t in
            ''.join(c.lower() if c.isalnum() else ' ' for c in text).split()
            if t]
    counts = {}
    for t in toks:
        if t in vocab:
            counts[t] = counts.get(t, 0) + 1
    lp = {c: tm['log_prior'][c] for c in tm['log_prior']}
    for c in lp:
        lprob = tm['log_prob'][c]
        for t, n in counts.items():
            lp[c] += n * lprob[vocab[t]]
    # log-odds spam vs ham
    lo = lp['1'] - lp['0']
    p = float(sigmoid(np.array(lo)))
    lprob_s, lprob_h = tm['log_prob']['1'], tm['log_prob']['0']
    why = sorted(((t, n * (lprob_s[vocab[t]] - lprob_h[vocab[t]]))
                  for t, n in counts.items()),
                 key=lambda kv: -abs(kv[1]))[:10]
    return p, why


def verdict(p):
    for thresh, name in VERDICTS:
        if p >= thresh:
            return name
    return 'CLEAN'


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ('url', 'text'):
        print(__doc__)
        sys.exit(2)
    mode, payload = sys.argv[1], ' '.join(sys.argv[2:])
    print('loading models (first run trains on the real feeds)...')
    m = get_models()
    if mode == 'url':
        p, feats, contrib, flags, (td, brand, bsub), lures = score_url(payload, m)
        print(f'\nURL: {payload}')
        print(f'score: {p:.3f}  ->  {verdict(p)}')
        for rule, floor in flags:
            print(f'  [RULE] {rule}  (floor {floor:.2f})')
        print(f'typosquat: closest brand "{brand}" at distance {td}'
              + ('  [BRAND-AS-SUBDOMAIN]' if bsub else ''))
        if lures:
            print(f'lure words: {", ".join(lures)}')
        print('\ntop contributing features (log-odds):')
        for name, c in contrib:
            print(f'  {name:18s} {feats[name]:>10.3f}  ({c:+.3f})')
    else:
        p, why = score_text(payload, m)
        print(f'\nmessage: {payload[:160]}')
        print(f'score: {p:.3f}  ->  {verdict(p)}')
        print('\ntop contributing tokens (log-odds):')
        for tok, c in why:
            print(f'  {tok:18s} ({c:+.3f})')


if __name__ == '__main__':
    main()
