"""Machine learning from scratch. Only numpy for array math.
Covers: standardization, Gaussian Naive Bayes, logistic regression
(full-batch gradient descent with L2), multinomial Naive Bayes with
TF-IDF, metrics, and stratified k-fold cross-validation."""
import math
import numpy as np
from collections import Counter


# ---------------------------------------------------------------- standardize
class Standardizer:
    def fit(self, X):
        self.mean_ = X.mean(axis=0)
        self.scale_ = X.std(axis=0)
        self.scale_[self.scale_ == 0.0] = 1.0  # constant feature -> zeros
        return self

    def transform(self, X):
        return (X - self.mean_) / self.scale_

    def fit_transform(self, X):
        return self.fit(X).transform(X)


# ------------------------------------------------------- Gaussian Naive Bayes
class GaussianNB:
    """P(x|y=c) = product of Gaussians. Fit by closed-form MLE."""

    def fit(self, X, y):
        self.classes_ = np.unique(y)
        self.theta_ = {}   # mean per class per feature
        self.sigma_ = {}   # var per class per feature
        self.prior_ = {}
        for c in self.classes_:
            Xc = X[y == c]
            self.theta_[c] = Xc.mean(axis=0)
            self.sigma_[c] = Xc.var(axis=0) + 1e-9  # floor: no zero-variance
            self.prior_[c] = Xc.shape[0] / X.shape[0]
        return self

    def _logpdf(self, X, mean, var):
        return -0.5 * (np.log(2 * math.pi * var) + (X - mean) ** 2 / var)

    def predict_log_proba(self, X):
        out = []
        for c in self.classes_:
            lp = self._logpdf(X, self.theta_[c], self.sigma_[c]).sum(axis=1)
            out.append(lp + math.log(self.prior_[c]))
        return np.column_stack(out)

    def predict_proba(self, X):
        lp = self.predict_log_proba(X)
        lp -= lp.max(axis=1, keepdims=True)
        e = np.exp(lp)
        return e / e.sum(axis=1, keepdims=True)

    def predict(self, X):
        return self.classes_[self.predict_proba(X).argmax(axis=1)]


# ---------------------------------------------------------- logistic regression
def sigmoid(z):
    out = np.empty_like(z, dtype=float)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    ez = np.exp(z[~pos])
    out[~pos] = ez / (1.0 + ez)
    return out


class LogisticRegression:
    """Binary logistic regression trained by full-batch gradient descent.

    Minimizes  -mean(y*log p + (1-y)*log(1-p)) + 0.5*l2*||w||^2
    with a 1/sqrt(t) learning-rate decay and early stopping on a
    validation split (patience). Bias term is not regularized.
    """

    def __init__(self, lr=0.5, l2=1.0, max_iter=2000, patience=50,
                 val_frac=0.15, seed=0, tol=1e-4):
        self.lr, self.l2 = lr, l2
        self.max_iter, self.patience = max_iter, patience
        self.val_frac, self.seed, self.tol = val_frac, seed, tol

    def _loss(self, Xb, y, w):
        p = sigmoid(Xb @ w)
        eps = 1e-12
        ce = -(y * np.log(p + eps) + (1 - y) * np.log(1 - p + eps)).mean()
        return ce + 0.5 * self.l2 * (w[1:] @ w[1:])

    def _grad(self, Xb, y, w):
        n = Xb.shape[0]
        p = sigmoid(Xb @ w)
        g = Xb.T @ (p - y) / n
        g[1:] += self.l2 * w[1:]
        return g

    def fit(self, X, y):
        rng = np.random.default_rng(self.seed)
        n = X.shape[0]
        idx = rng.permutation(n)
        nv = max(1, int(n * self.val_frac))
        vi, ti = idx[:nv], idx[nv:]
        Xb = np.column_stack([np.ones(X.shape[0]), X])
        Xtr, ytr, Xva, yva = Xb[ti], y[ti], Xb[vi], y[vi]

        w = np.zeros(Xb.shape[1])
        best, best_w, bad = float('inf'), w.copy(), 0
        for t in range(1, self.max_iter + 1):
            g = self._grad(Xtr, ytr, w)
            w = w - (self.lr / math.sqrt(t)) * g
            vl = self._loss(Xva, yva, w)
            if vl < best - self.tol:
                best, best_w, bad = vl, w.copy(), 0
            else:
                bad += 1
                if bad >= self.patience:
                    break
        self.coef_ = best_w
        self.n_iter_ = t
        self.val_loss_ = best
        return self

    def decision(self, X):
        Xb = np.column_stack([np.ones(X.shape[0]), X])
        return Xb @ self.coef_

    def predict_proba(self, X):
        p = sigmoid(self.decision(X))
        return np.column_stack([1 - p, p])

    def predict(self, X):
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


# --------------------------------------------- multinomial NB (text classifier)
class CountVectorizer:
    """Bag-of-words with min_df pruning, from scratch."""

    def __init__(self, min_df=2):
        self.min_df = min_df

    @staticmethod
    def tokenize(text):
        return [t for t in
                ''.join(c.lower() if c.isalnum() else ' ' for c in text).split()
                if t]

    def fit(self, texts):
        df = Counter()
        for t in texts:
            for tok in set(self.tokenize(t)):
                df[tok] += 1
        vocab = [tok for tok, c in df.items() if c >= self.min_df]
        self.vocab_ = {tok: i for i, tok in enumerate(sorted(vocab))}
        return self

    def transform(self, texts):
        import numpy as np
        X = np.zeros((len(texts), len(self.vocab_)))
        for i, t in enumerate(texts):
            for tok in self.tokenize(t):
                j = self.vocab_.get(tok)
                if j is not None:
                    X[i, j] += 1
        return X

    def fit_transform(self, texts):
        return self.fit(texts).transform(texts)


class TfidfTransformer:
    """log-tf * smoothed idf, L2 row-normalized."""

    def fit(self, X):
        n = X.shape[0]
        df = (X > 0).sum(axis=0)
        self.idf_ = np.log((1 + n) / (1 + df)) + 1.0
        return self

    def transform(self, X):
        tf = np.log1p(X)
        out = tf * self.idf_
        norm = np.linalg.norm(out, axis=1, keepdims=True)
        norm[norm == 0] = 1.0
        return out / norm

    def fit_transform(self, X):
        return self.fit(X).transform(X)


class MultinomialNB:
    """Textbook multinomial NB with Laplace smoothing, in log space."""

    def __init__(self, alpha=1.0):
        self.alpha = alpha

    def fit(self, X, y):
        self.classes_ = np.unique(y)
        self.log_prior_ = {}
        self.log_prob_ = {}   # per class: log P(token|class)
        for c in self.classes_:
            Xc = X[y == c]
            self.log_prior_[c] = math.log(Xc.shape[0] / X.shape[0])
            smoothed = Xc.sum(axis=0) + self.alpha
            self.log_prob_[c] = np.log(smoothed / smoothed.sum())
        return self

    def predict_log_proba(self, X):
        return np.column_stack([
            X @ self.log_prob_[c] + self.log_prior_[c] for c in self.classes_])

    def predict(self, X):
        lp = self.predict_log_proba(X)
        return self.classes_[lp.argmax(axis=1)]

    def predict_proba(self, X):
        lp = self.predict_log_proba(X)
        lp -= lp.max(axis=1, keepdims=True)
        e = np.exp(lp)
        return e / e.sum(axis=1, keepdims=True)

    def top_tokens(self, vec, class_label, k=10):
        """Most incriminating tokens for one class (log-count-ratio)."""
        other = [c for c in self.classes_ if c != class_label][0]
        ratio = self.log_prob_[class_label] - self.log_prob_[other]
        idx = np.argsort(ratio)[::-1][:k]
        inv = {j: t for t, j in vec.vocab_.items()}
        return [(inv[j], float(ratio[j])) for j in idx]


# ------------------------------------------------------------------- metrics
def confusion_matrix(y_true, y_pred):
    tp = int(((y_true == 1) & (y_pred == 1)).sum())
    tn = int(((y_true == 0) & (y_pred == 0)).sum())
    fp = int(((y_true == 0) & (y_pred == 1)).sum())
    fn = int(((y_true == 1) & (y_pred == 0)).sum())
    return {'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn}


def prf(y_true, y_pred):
    m = confusion_matrix(y_true, y_pred)
    p = m['tp'] / max(m['tp'] + m['fp'], 1)
    r = m['tp'] / max(m['tp'] + m['fn'], 1)
    f1 = 2 * p * r / max(p + r, 1e-12)
    acc = (m['tp'] + m['tn']) / max(len(y_true), 1)
    return {'accuracy': acc, 'precision': p, 'recall': r, 'f1': f1, **m}


def roc_auc(y_true, scores):
    """Mann-Whitney rank form with average-rank tie correction.

    AUC = P(score_pos > score_neg) + 0.5 * P(tie). Computed as
    (R - P(P+1)/2) / (P*N) where R is the sum of (average) ranks of the
    positive class. Exact for ties; a trapezoid over thresholds without
    tie handling scores all-tied inputs as 0 instead of 0.5.
    """
    y_true = np.asarray(y_true)
    scores = np.asarray(scores)
    order = np.argsort(scores, kind='mergesort')
    s = scores[order]
    n = len(s)
    ranks = np.empty(n)
    i = 0
    while i < n:
        j = i
        while j + 1 < n and s[j + 1] == s[i]:
            j += 1
        ranks[i:j + 1] = (i + j) / 2.0 + 1.0  # 1-based average rank
        i = j + 1
    rank_of = np.empty(n)
    rank_of[order] = ranks
    pos = y_true == 1
    P, N = pos.sum(), (~pos).sum()
    if P == 0 or N == 0:
        return float('nan')
    R = rank_of[pos].sum()
    return float((R - P * (P + 1) / 2.0) / (P * N))


def pr_auc(y_true, scores):
    order = np.argsort(-scores)
    y = y_true[order]
    tp = np.cumsum(y == 1)
    fp = np.cumsum(y == 0)
    prec = tp / np.maximum(tp + fp, 1)
    rec = tp / max((y_true == 1).sum(), 1)
    prec = np.concatenate([[1.0], prec])
    rec = np.concatenate([[0.0], rec])
    return float(np.trapz(prec, rec))


# --------------------------------------------------------------- cross-validate
def stratified_kfold(y, k, seed=0):
    rng = np.random.default_rng(seed)
    folds = [[] for _ in range(k)]
    for c in np.unique(y):
        idx = np.where(y == c)[0]
        rng.shuffle(idx)
        for i, j in enumerate(idx):
            folds[i % k].append(j)
    for f in folds:
        f.sort()
    return [(np.array([j for i, f in enumerate(folds) if i != fi for j in f]),
             np.array(folds[fi])) for fi in range(k)]


def cross_val_score(make_model, X, y, k=5, seed=0):
    """make_model: () -> fresh unfitted model with .fit/.predict/.predict_proba."""
    scores = []
    for tr, te in stratified_kfold(y, k, seed):
        m = make_model()
        m.fit(X[tr], y[tr])
        proba = m.predict_proba(X[te])
        scores.append(roc_auc(y[te], proba[:, 1]))
    return np.array(scores)
