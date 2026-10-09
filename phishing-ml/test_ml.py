"""Validation battery for expedition 25: ML from scratch + phishing triage.

Sections:
  A. string/distance primitives      (Damerau-Levenshtein, entropy)
  B. feature extraction fixtures      (IP, punycode, userinfo, brand tricks)
  C. optimizer correctness            (gradient check, separable convergence)
  D. model unit checks                (GaussianNB, MultinomialNB, vectorizer)
  E. metrics + CV plumbing            (AUC edge cases, stratification)
  F. real-data end-to-end             (URLhaus+Tranco, SMS spam)
  G. adversarial triage               (hand-crafted phish vs legit, short paths)
"""
import math
import numpy as np

from features import (damerau_levenshtein, shannon_entropy, extract_features,
                      typosquat_features, FEATURE_NAMES)
from ml import (Standardizer, GaussianNB, LogisticRegression, MultinomialNB,
                CountVectorizer, confusion_matrix, prf, roc_auc, pr_auc,
                stratified_kfold, sigmoid)

PASS = []
FAIL = []


def check(name, cond, detail=''):
    (PASS if cond else FAIL).append(name)
    print(('PASS ' if cond else 'FAIL ') + name + (f'  [{detail}]' if detail else ''))


# ------------------------------------------------ A. distance + entropy
check('dl: identical', damerau_levenshtein('paypal', 'paypal') == 0)
check('dl: substitution', damerau_levenshtein('paypa1', 'paypal') == 1)
check('dl: transposition', damerau_levenshtein('paypla', 'paypal') == 1)
check('dl: insertion', damerau_levenshtein('gogle', 'google') == 1)
check('dl: kitten/sitting', damerau_levenshtein('kitten', 'sitting') == 3)
check('dl: cutoff exact<=k', damerau_levenshtein('paypa1', 'paypal', max_dist=5) == 1)
check('dl: cutoff early-exit', damerau_levenshtein('kitten', 'sitting', max_dist=2) == 3)
check('dl: cutoff len-diff', damerau_levenshtein('abcdefgh', 'xy', max_dist=5) == 6)
check('dl: symmetry',
      damerau_levenshtein('abc', 'abd') == damerau_levenshtein('abd', 'abc'))
check('entropy: constant', shannon_entropy('aaaaaaaa') == 0.0)
check('entropy: fair coin', abs(shannon_entropy('ab') - 1.0) < 1e-9)
check('entropy: empty', shannon_entropy('') == 0.0)

# ------------------------------------------------ B. feature fixtures
f = extract_features('http://59.180.141.251:37929/i')
check('feat: ip literal', f['is_ip'] == 1 and f['has_port'] == 1 and f['nonstd_port'] == 1)
check('feat: ip digits', f['host_digits'] == 11)
f = extract_features('http://xn--pypal-4ve.com/login')
check('feat: punycode', f['punycode'] == 1)
f = extract_features('http://user:pass@evil.com/login')
check('feat: userinfo', f['userinfo_present'] == 1 and f['has_at'] == 1)
f = extract_features('https://paypal.evil-bank.ru/signin')
check('feat: brand subdomain', f['brand_subdomain'] == 1)
check('feat: lure words', extract_features(
    'https://x.top/verify-account-login')['lure_words'] >= 2)
check('feat: risky tld', extract_features('https://x.xyz/')['risky_tld'] == 1)
check('feat: safe tld', extract_features('https://x.com/')['risky_tld'] == 0)
check('feat: risky ext', extract_features('https://x.com/a.exe')['risky_ext'] == 1)
check('feat: hex escapes', extract_features('https://x.com/%2e%2e/')['hex_escapes'] == 2)
d, brand, _ = typosquat_features('paypa1-login.verify-account.top')
check('typo: finds paypal', brand == 'paypal' and d == 1, f'{brand}@{d}')
d, brand, _ = typosquat_features('google.com')
check('typo: exact brand', brand == 'google' and d == 0)
check('feat: names stable', len(FEATURE_NAMES) == 30)
f = extract_features('https://www.google.com/')
check('feat: all numeric finite',
      all(math.isfinite(float(f[n])) for n in FEATURE_NAMES))

# ------------------------------------------------ C. optimizer
rng = np.random.default_rng(0)
Xg = rng.normal(size=(40, 5))
yg = (rng.random(40) < 0.5).astype(int)


def num_grad(model, Xb, y, w, eps=1e-6):
    g = np.zeros_like(w)
    for j in range(len(w)):
        wp, wm = w.copy(), w.copy()
        wp[j] += eps
        wm[j] -= eps
        g[j] = (model._loss(Xb, y, wp) - model._loss(Xb, y, wm)) / (2 * eps)
    return g


tmp = LogisticRegression()
Xb = np.column_stack([np.ones(len(Xg)), Xg])
w0 = rng.normal(size=6) * 0.5
ag = tmp._grad(Xb, yg, w0)
ng = num_grad(tmp, Xb, yg, w0)
check('logreg: analytic grad == numeric grad',
      np.allclose(ag, ng, rtol=1e-4, atol=1e-6),
      f'max|diff|={np.abs(ag - ng).max():.2e}')

Xs_sep = np.array([[-3.0], [-2.0], [-1.0], [1.0], [2.0], [3.0]])
ys_sep = np.array([0, 0, 0, 1, 1, 1])
msep = LogisticRegression(lr=0.5, l2=0.01, max_iter=500,
                          val_frac=0.34).fit(Standardizer().fit_transform(Xs_sep), ys_sep)
check('logreg: separable -> 100% train',
      (msep.predict(Standardizer().fit_transform(Xs_sep)) == ys_sep).all())
check('logreg: loss decreases', msep.val_loss_ < math.log(2),
      f'val_loss={msep.val_loss_:.4f} < {math.log(2):.4f}=log2')
check('sigmoid: numerically stable at extremes',
      (lambda p: bool(not np.isnan(p).any() and not np.isinf(p).any()
                      and p[0] > 0.999 and p[1] < 0.001 and p[2] == 0.5))(
          sigmoid(np.array([1000.0, -1000.0, 0.0]))))

# ------------------------------------------------ D. model units
X1 = rng.normal(loc=0.0, scale=1.0, size=(200, 3))
X2 = rng.normal(loc=5.0, scale=1.0, size=(200, 3))
Xg2 = np.vstack([X1, X2])
yg2 = np.array([0] * 200 + [1] * 200)
gnb = GaussianNB().fit(Xg2, yg2)
check('gaussnb: recovers means',
      np.allclose(gnb.theta_[0], 0, atol=0.25) and np.allclose(gnb.theta_[1], 5, atol=0.25))
check('gaussnb: recovers vars',
      np.allclose(gnb.sigma_[0], 1, atol=0.25) and np.allclose(gnb.sigma_[1], 1, atol=0.25))
check('gaussnb: proba rows sum to 1',
      np.allclose(gnb.predict_proba(Xg2[:5]).sum(axis=1), 1.0))

texts = (['free prize claim now winner'] * 20 + ['hey are we still on for lunch'] * 20)
ylab = np.array([1] * 20 + [0] * 20)
vec = CountVectorizer(min_df=2).fit(texts)
Xt = vec.transform(texts)
mnb = MultinomialNB().fit(Xt, ylab)
check('multinb: separates toy corpus',
      (mnb.predict(Xt) == ylab).all())
top = mnb.top_tokens(vec, 1, 3)
check('multinb: top spam token sensible', top[0][0] in
      {'free', 'prize', 'claim', 'winner', 'now'}, str(top))
check('vec: min_df prunes', 'zxqv' not in vec.vocab_)
check('vec: tokenize lowercases',
      CountVectorizer.tokenize('Hello, WORLD!') == ['hello', 'world'])
check('std: zero mean unit var',
      (lambda s, Z: abs(Z.mean()) < 1e-9 and abs(Z.std() - 1) < 1e-9)(
          Standardizer(), Standardizer().fit_transform(rng.normal(size=(500, 4)))))
Zc = Standardizer().fit_transform(np.ones((10, 3)))
check('std: constant feature -> zeros', (Zc == 0).all())

# ------------------------------------------------ E. metrics + CV
yt = np.array([0, 0, 1, 1])
check('auc: perfect', roc_auc(yt, np.array([0.1, 0.2, 0.8, 0.9])) == 1.0)
check('auc: chance', abs(roc_auc(yt, np.array([0.5, 0.5, 0.5, 0.5])) - 0.5) < 1e-9)
check('auc: worst', roc_auc(yt, np.array([0.9, 0.8, 0.2, 0.1])) == 0.0)
m_ = confusion_matrix(np.array([1, 1, 0, 0]), np.array([1, 0, 1, 0]))
check('confusion: counts', m_ == {'tp': 1, 'tn': 1, 'fp': 1, 'fn': 1}, str(m_))
r_ = prf(np.array([1, 1, 0, 0]), np.array([1, 0, 1, 0]))
check('prf: known values',
      abs(r_['precision'] - 0.5) < 1e-9 and abs(r_['recall'] - 0.5) < 1e-9
      and abs(r_['f1'] - 0.5) < 1e-9 and abs(r_['accuracy'] - 0.5) < 1e-9)
check('pr_auc: sane range', 0.0 <= pr_auc(yt, np.array([0.1, 0.2, 0.8, 0.9])) <= 1.0)
ycv = np.array([0] * 100 + [1] * 40)
folds = stratified_kfold(ycv, 5, seed=1)
seen = []
ok_ratio = True
for tr, te_ in folds:
    seen.extend(te_.tolist())
    ratio = (ycv[te_] == 1).mean()
    ok_ratio &= abs(ratio - 0.4 / 1.4) < 0.08
check('cv: every idx tested once', sorted(seen) == list(range(140)))
check('cv: class ratio preserved', ok_ratio)

print(f'\n{len(PASS)} passed, {len(FAIL)} failed')
if FAIL:
    print('FAILURES:', FAIL)
    raise SystemExit(1)
