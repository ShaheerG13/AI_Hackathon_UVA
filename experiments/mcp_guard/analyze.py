"""
analyze.py — probe the decision-point activations.

  A. PRESENCE: is an injected instruction in context?   (clean vs poisoned)
  B. INTENT:   among poisoned prompts, will the model FOLLOW it? (follow_rate >= 0.5)

Both are tested on HELD-OUT injection templates (spec["test_templates"]), so a
probe can't win by memorising phrasings. Every probe is compared against:
  - shuffled-label control (from probes.layer_sweep)  -> should be ~chance
  - TF-IDF logistic regression on the prompt text     -> what a text monitor sees
  - vector-only baseline (description vs output)      -> trivial-feature check (B)

    python analyze.py            # or: python analyze.py --pilot
"""

import argparse
import json
import pickle
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import spearmanr
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

import probes
import sandbox as sb

OUT = Path(__file__).parent / "results"


def text_baseline(tr_texts, ytr, te_texts, yte):
    vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
    Xtr, Xte = vec.fit_transform(tr_texts), vec.transform(te_texts)
    clf = LogisticRegression(max_iter=2000).fit(Xtr, ytr)
    return roc_auc_score(yte, clf.predict_proba(Xte)[:, 1])


def run(name, acts, rows, tr, te, y):
    ytr, yte = y[tr], y[te]
    print(f"\n=== {name}: train n={len(tr)} (pos {ytr.mean():.2f})  "
          f"test n={len(te)} (pos {yte.mean():.2f})")
    if len(set(ytr)) < 2 or len(set(yte)) < 2:
        print("  one class only on a split — nothing to probe. (See follow rates.)")
        return None
    sweep = probes.layer_sweep(acts[tr], ytr, acts[te], yte, control=True)
    best = max(sweep, key=lambda r: r["auroc"])
    print("  layer  auroc  acc   ctrl_acc")
    for r in sweep:
        mark = " <- best" if r is best else ""
        print(f"  {r['layer']:>5}  {r['auroc']:.3f}  {r['test_acc']:.2f}  {r['control_acc']:.2f}{mark}")
    texts = [rows[i]["prompt"] for i in range(len(rows))]
    tb = text_baseline([texts[i] for i in tr], ytr, [texts[i] for i in te], yte)
    print(f"  TF-IDF text baseline AUROC: {tb:.3f}")
    return {"sweep": sweep, "best": best, "text_auroc": tb}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    args = ap.parse_args()
    tag = "pilot_" if args.pilot else ""

    spec = sb.load_scenario(sb.MCP_SCENARIO)
    rows = [json.loads(l) for l in open(OUT / f"{tag}decisions.jsonl")]
    acts = np.load(OUT / f"{tag}acts.npy").astype(np.float32)
    test_t = set(spec["test_templates"])
    vec = np.array([r["vector"] for r in rows])
    fr = np.array([r["follow_rate"] for r in rows])
    is_test = np.array([r["template"] in test_t if r["template"] is not None
                        else r["status_i"] in (3, 4) for r in rows])   # clean: hold out 2 status texts

    print("follow rates by vector:")
    for v in ("clean", "description", "output"):
        m = vec == v
        print(f"  {v:<12} n={m.sum():<4} mean={fr[m].mean():.2f}  frac>=0.5={np.mean(fr[m] >= .5):.2f}")
    print("follow rate by template (desc / output):")
    for t in range(len(spec["injections"])):
        d = fr[(vec == "description") & (np.array([r["template"] for r in rows]) == t)]
        o = fr[(vec == "output") & (np.array([r["template"] for r in rows]) == t)]
        print(f"  t{t:<2}{'*' if t in test_t else ' '} {d.mean():.2f} / {o.mean():.2f}   "
              f"{spec['injections'][t][:60]}")

    results = {}
    # A. presence
    y = (vec != "clean").astype(int)
    idx = np.arange(len(rows))
    results["presence"] = run("A. PRESENCE (clean vs poisoned)", acts, rows,
                              idx[~is_test], idx[is_test], y)

    # B. intent, poisoned only
    inj = idx[vec != "clean"]
    y = (fr >= 0.5).astype(int)
    tr, te = inj[~is_test[inj]], inj[is_test[inj]]
    resB = run("B. INTENT (followed vs ignored, poisoned only)", acts, rows, tr, te, y)
    results["intent"] = resB
    if resB:
        base = roc_auc_score(y[te], (vec[te] == "output").astype(float)) if len(set(vec[te])) > 1 else float("nan")
        print(f"  vector-only baseline AUROC: {base:.3f}")
        L = resB["best"]["layer"]
        probe = probes.train_probe(acts[tr, L], y[tr], acts[te, L], y[te])["model"]
        score = probe.predict_proba(acts[te, L])[:, 1]
        rho = spearmanr(score, fr[te]).correlation
        print(f"  best-layer probe score vs continuous follow_rate: spearman rho={rho:.3f}")
        resB["vector_baseline"] = base
        with open(OUT / f"{tag}intent_probe.pkl", "wb") as f:
            pickle.dump({"layer": L, "probe": probe,
                         "direction": probes.diff_in_means(acts[tr, L], y[tr])}, f)

    if results["presence"]:
        L = results["presence"]["best"]["layer"]
        probe = probes.train_probe(acts[idx[~is_test], L], (vec != "clean")[~is_test].astype(int),
                                   acts[idx[is_test], L], (vec != "clean")[is_test].astype(int))["model"]
        with open(OUT / f"{tag}presence_probe.pkl", "wb") as f:
            pickle.dump({"layer": L, "probe": probe}, f)

    fig, ax = plt.subplots(figsize=(7, 4))
    for key, label in (("presence", "A. injection present"), ("intent", "B. will follow")):
        r = results.get(key)
        if r:
            ax.plot([s["layer"] for s in r["sweep"]], [s["auroc"] for s in r["sweep"]], label=f"{label} (probe)")
            ax.axhline(r["text_auroc"], ls="--", lw=1, color=ax.lines[-1].get_color(),
                       label=f"{label} (TF-IDF text)")
    ax.axhline(0.5, color="gray", lw=0.8)
    ax.set_xlabel("layer"); ax.set_ylabel("held-out-template AUROC"); ax.set_ylim(0.3, 1.02)
    ax.legend(fontsize=8); ax.set_title(f"Decision-point probes, {rows[0].get('model', '?').split('/')[-1]}")
    fig.tight_layout(); fig.savefig(OUT / f"{tag}layer_sweep.png", dpi=150)

    summary = {k: (None if v is None else {"best_layer": v["best"]["layer"], "probe_auroc": v["best"]["auroc"],
                                          "text_auroc": v["text_auroc"],
                                          "vector_baseline": v.get("vector_baseline")})
               for k, v in results.items()}
    (OUT / f"{tag}summary.json").write_text(json.dumps(summary, indent=2))
    print("\nsummary:", json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
