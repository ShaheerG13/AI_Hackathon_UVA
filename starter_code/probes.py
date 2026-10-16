"""
probes.py — the small amount of maths you need for probing and steering.

    res = train_probe(X_train, y_train, X_test, y_test)    # one layer
    sweep = layer_sweep(acts_train, y_train, acts_test, y_test)
    d = diff_in_means(X, y)                                # a direction
    scores = project(X, d)

All plain NumPy + scikit-learn. No model needed, so you can test ideas fast.
"""

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler


def unit(v):
    v = np.asarray(v, dtype=float)
    n = np.linalg.norm(v)
    return v if n == 0 else v / n


def diff_in_means(X, y):
    """Direction from the class-0 mean to the class-1 mean, unit length.
    The simplest 'concept direction' there is — and surprisingly strong."""
    X, y = np.asarray(X, dtype=float), np.asarray(y)
    return unit(X[y == 1].mean(axis=0) - X[y == 0].mean(axis=0))


def project(X, d):
    """How far each row points along direction d (a scalar per row)."""
    return np.asarray(X, dtype=float) @ unit(d)


def remove_direction(X, d):
    """Ablation on stored activations: subtract each row's component along d."""
    X, d = np.asarray(X, dtype=float), unit(d)
    return X - np.outer(X @ d, d)


def cosine(a, b):
    return float(unit(a) @ unit(b))


def train_probe(X_train, y_train, X_test, y_test, seed=0):
    """
    A linear probe: logistic regression on activations. Returns test accuracy
    and AUROC — always judge a probe on data it did NOT train on.
    """
    clf = make_pipeline(StandardScaler(),
                        LogisticRegression(max_iter=2000, random_state=seed))
    clf.fit(X_train, y_train)
    p = clf.predict_proba(X_test)[:, 1]
    return {
        "test_acc": float((clf.predict(X_test) == np.asarray(y_test)).mean()),
        "auroc": float(roc_auc_score(y_test, p)) if len(set(y_test)) == 2 else float("nan"),
        "model": clf,
    }


def layer_sweep(acts_train, y_train, acts_test, y_test, control=True, seed=0):
    """
    Train one probe per layer. acts_* have shape (n, n_layers + 1, d_model).

    With control=True, also trains on SHUFFLED training labels at each layer.
    That's the baseline: a probe on shuffled labels should score ~chance. If
    your real probe isn't well above it, you haven't found anything.
    """
    rng = np.random.default_rng(seed)
    rows = []
    for layer in range(acts_train.shape[1]):
        real = train_probe(acts_train[:, layer], y_train, acts_test[:, layer], y_test, seed)
        row = {"layer": layer, "test_acc": real["test_acc"], "auroc": real["auroc"]}
        if control:
            shuffled = rng.permutation(y_train)
            ctrl = train_probe(acts_train[:, layer], shuffled, acts_test[:, layer], y_test, seed)
            row["control_acc"] = ctrl["test_acc"]
        rows.append(row)
    return rows


def class_gap(X, y, d):
    """Distance between the two class means along direction d. Use it as the
    unit for steering strength: alpha = k * gap means 'push k times as far as
    the difference between the classes'. A raw number like alpha=4 means very
    different things on different models, because activation sizes differ."""
    s = project(X, d)
    y = np.asarray(y)
    return float(abs(s[y == 1].mean() - s[y == 0].mean()))


def best_layer(sweep, key="test_acc", min_layer=1):
    """Layer with the highest score. Skips layer 0 by default: that's the raw
    token embeddings, and you can't steer or ablate there — if layer 0 wins,
    the classes differ in their *words*, which is worth knowing in itself."""
    return max((r for r in sweep if r["layer"] >= min_layer), key=lambda r: r[key])["layer"]
