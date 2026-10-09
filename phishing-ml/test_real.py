"""End-to-end validation on real data + adversarial triage (slow: ~2-3 min).

F. real-data training: URLhaus(+synthetic phish)/Tranco URL model and
   UCI SMS spam text model — asserts honest metric floors.
G. adversarial: hand-written phish URLs (DISJOINT from the synthetic
   generator's templates) must score above legit URLs; the rule layer must
   fire on every phish and on no legit URL.
"""
import numpy as np

from data import build_url_dataset, load_sms
from features import featurize, FEATURE_NAMES, extract_features
from ml import (Standardizer, LogisticRegression, MultinomialNB,
                CountVectorizer, prf, roc_auc)
from triage import score_url, score_text, verdict
import triage as triage_mod

PASS, FAIL = [], []


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(('PASS ' if cond else 'FAIL ') + name + (f'  [{detail}]' if detail else ''))


# ------------------------------------------------ F1. URL model on real feeds
urls, y = build_url_dataset(n_benign=8000, n_synth=1000)
X = featurize(urls)
rng = np.random.default_rng(7)
idx = rng.permutation(len(y))
te, tr = idx[:1800], idx[1800:]
std = Standardizer().fit(X[tr])
Xs = std.transform(X)
m = LogisticRegression(lr=0.5, l2=1.0, max_iter=2000).fit(Xs[tr], y[tr])
p = m.predict_proba(Xs[te])[:, 1]
r = prf(y[te], (p >= 0.5).astype(int))
check('url: accuracy >= 0.93', r['accuracy'] >= 0.93, f"{r['accuracy']:.4f}")
check('url: ROC-AUC >= 0.97', roc_auc(y[te], p) >= 0.97, f"{roc_auc(y[te], p):.4f}")
check('url: precision >= 0.95', r['precision'] >= 0.95, f"{r['precision']:.4f}")
w = dict(zip(FEATURE_NAMES, m.coef_[1:]))
check('url: lure_words learned positive', w['lure_words'] > 0.03, f"{w['lure_words']:+.4f}")
check('url: risky_tld learned positive', w['risky_tld'] > 0.01, f"{w['risky_tld']:+.4f}")
check('url: is_ip learned positive', w['is_ip'] > 0.05, f"{w['is_ip']:+.4f}")
check('url: scheme leak gone (|w|<0.05)', abs(w['is_https']) < 0.05, f"{w['is_https']:+.4f}")

# ------------------------------------------------ F2. text model on SMS corpus
texts, ys = load_sms()
vec = CountVectorizer(min_df=3).fit(texts)
Xt = vec.transform(texts)
idx = rng.permutation(len(ys))
te2, tr2 = idx[:1115], idx[1115:]
nb = MultinomialNB().fit(Xt[tr2], ys[tr2])
p2 = nb.predict_proba(Xt[te2])[:, 1]
r2 = prf(ys[te2], (p2 >= 0.5).astype(int))
check('text: accuracy >= 0.96', r2['accuracy'] >= 0.96, f"{r2['accuracy']:.4f}")
check('text: ROC-AUC >= 0.97', roc_auc(ys[te2], p2) >= 0.97, f"{roc_auc(ys[te2], p2):.4f}")
check('text: f1 >= 0.93', r2['f1'] >= 0.93, f"{r2['f1']:.4f}")

# ------------------------------------------------ G. adversarial triage
# Hand-written, disjoint from synthetic_brand_phish templates.
PHISH = [
    'https://paypa1-login.verify-account.top/signin',
    'https://secure-appleid-support.com/verify',
    'https://chaseonline.evil-bank.ru/login',
    'http://192.168.90.14:8080/update',
    'https://amaz0n-prize-claim.xyz/win',
    'https://docusign-secure-doc.sbs/sign',
    'http://user:pass@secure-update.com/login',
    'https://xn--pypal-4ve.com/signin',
]
LEGIT = [
    'https://www.google.com/search?q=weather',
    'https://www.amazon.com/gp/cart/view.html',
    'https://github.com/torvalds/linux',
    'https://www.nytimes.com/2026/10/08/us/politics/x.html',
    'https://en.wikipedia.org/wiki/Phishing',
    'https://www.chase.com/personal/checking',
]

models = {
    'url': {'std_mean': std.mean_.tolist(), 'std_scale': std.scale_.tolist(),
            'coef': m.coef_.tolist(), 'names': FEATURE_NAMES},
    'text': {'vocab': vec.vocab_,
             'log_prob': {str(c): nb.log_prob_[c].tolist() for c in nb.classes_},
             'log_prior': {str(c): nb.log_prior_[c] for c in nb.classes_},
             'classes': [int(c) for c in nb.classes_]},
}


def model_only(u):
    f = extract_features(u)
    x = np.array([float(f[n]) for n in FEATURE_NAMES])
    xs = (x - std.mean_) / std.scale_
    return float(1 / (1 + np.exp(-(m.coef_[0] + xs @ m.coef_[1:]))))


phish_scores = [model_only(u) for u in PHISH]
legit_scores = [model_only(u) for u in LEGIT]
check('adv: mean(phish) > mean(legit)+0.10',
      np.mean(phish_scores) > np.mean(legit_scores) + 0.10,
      f'{np.mean(phish_scores):.3f} vs {np.mean(legit_scores):.3f}')
# Model-only floor is deliberately weak: the punycode URL scores ~0.39 from
# the model alone (punycode is rare in training, so it carries no learned
# weight) — that shape is *designed* to be resolved by the rule layer
# (PUNYCODE + lure -> 0.70 floor). The system-level guarantees are the
# 'final' checks below.
check('adv: every phish model-score >= 0.30', min(phish_scores) >= 0.30,
      f'min={min(phish_scores):.3f} (punycode case is rule-resolved)')

final_phish, final_legit = [], []
for u in PHISH:
    s, _f, _c, flags, _t, _l = score_url(u, models)
    final_phish.append(s)
    check(f'adv: rule fires on phish [{u[:45]}]', len(flags) > 0, str([f[0][:40] for f in flags]))
for u in LEGIT:
    s, _f, _c, flags, _t, _l = score_url(u, models)
    final_legit.append(s)
    check(f'adv: no rule fires on legit [{u[:45]}]', len(flags) == 0)
check('adv: all phish final >= 0.65 (SUSPICIOUS+)', min(final_phish) >= 0.65,
      f'min={min(final_phish):.3f}')
check('adv: all legit final <= 0.60', max(final_legit) <= 0.60,
      f'max={max(final_legit):.3f}')

# text adversarial
SPAM = [
    'CONGRATS! You have won a $1000 Walmart gift card. Claim your prize now at bit.ly/xyz — limited time offer!',
    'URGENT: your bank account has been suspended. Verify your identity immediately: secure-bank-login.top',
    'Free iPhone 17 Pro! Click here to claim: apple-prize-winner.xyz. Pay only $1 shipping.',
]
HAM = [
    'Hey, are we still on for lunch tomorrow? Let me know what time works.',
    'Your package arrives Thursday. Track it in the app.',
    'Mom called, she wants us over for dinner Sunday.',
]
for t in SPAM:
    s, _ = score_text(t, models)
    check(f'adv: spam text scores >= 0.70 [{t[:40]}]', s >= 0.70, f'{s:.3f}')
for t in HAM:
    s, _ = score_text(t, models)
    check(f'adv: ham text scores <= 0.30 [{t[:40]}]', s <= 0.30, f'{s:.3f}')

print(f'\n{len(PASS)} passed, {len(FAIL)} failed')
if FAIL:
    print('FAILURES:', FAIL)
    raise SystemExit(1)
