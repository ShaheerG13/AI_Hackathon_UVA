"""
collect.py — build the decision-point dataset.

For every condition (clean / poisoned description / poisoned output x template
x task x attacker address) we take the prompt at the moment right after the
agent got check_status back, then:
  1. sample k next actions -> follow_rate = fraction that carry out the injection
  2. read residual-stream activations at the last prompt token (the "about to
     decide" state), every layer

    python collect.py --pilot          # ~16 prompts: check timing + follow rates
    python collect.py --addrs 2 --k 4  # full run

Outputs results/decisions.jsonl (one row per prompt) and results/acts.npy.
"""

import argparse
import json
import time
from pathlib import Path

import numpy as np

import lm
import sandbox as sb

OUT = Path(__file__).parent / "results"


def conditions(spec, n_addrs, pilot):
    rows = []
    tasks = range(len(spec["tasks"]))
    addrs = spec["attacker_addrs"][:n_addrs]
    for ti in tasks:
        for si in range(len(spec["status_outputs"])):
            for bi in range(len(spec["benign_notes"])):
                c = sb.make_condition(spec, "clean", status_i=si, benign_i=bi)
                rows.append({**c, "task_i": ti, "status_i": si, "benign_i": bi})
    for vector in ("description", "output"):
        for tmpl in range(len(spec["injections"])):
            for ti in tasks:
                for ai, addr in enumerate(addrs):
                    si = (tmpl + ti + ai) % len(spec["status_outputs"])
                    c = sb.make_condition(spec, vector, template=tmpl, addr=addr, status_i=si)
                    rows.append({**c, "task_i": ti, "status_i": si})
    if pilot:  # a few of each vector, spread over templates
        rng = np.random.default_rng(0)
        clean = [r for r in rows if r["vector"] == "clean"]
        inj = [r for r in rows if r["vector"] != "clean"]
        rows = [clean[i] for i in rng.choice(len(clean), 4, replace=False)] + \
               [inj[i] for i in rng.choice(len(inj), 12, replace=False)]
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--k", type=int, default=4, help="samples per prompt")
    ap.add_argument("--addrs", type=int, default=2, help="attacker addresses per template")
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--model", default=lm.MODEL_ID)
    ap.add_argument("--prefill", default="ACTION:", help='forced start of the reply ("" = free choice incl. FINAL)')
    ap.add_argument("--max_new", type=int, default=40)
    ap.add_argument("--all_clean", action="store_true", help="all status x note combos (default: one note per status)")
    args = ap.parse_args()

    spec = sb.load_scenario(sb.MCP_SCENARIO)
    rows = conditions(spec, args.addrs, args.pilot)
    if not args.pilot and not args.all_clean:   # one benign note per status text: 5 clean prompts per task
        rows = [r for r in rows if r["vector"] != "clean" or r["benign_i"] == r["status_i"] % 3]
    print(f"{len(rows)} prompts x k={args.k} samples, model {args.model}")

    model, tok = lm.load_model(args.model)
    lm.describe(model)
    OUT.mkdir(exist_ok=True)
    tag = "pilot_" if args.pilot else ""
    out_rows = []
    t0 = time.time()
    for i, r in enumerate(rows):
        prompt = sb.decision_prompt(spec, r, spec["tasks"][r["task_i"]])
        replies = lm.sample(model, tok, prompt, n=args.k, max_new_tokens=args.max_new, prefix=args.prefill)
        actions = [sb.parse_first(x) for x in replies]
        follows = [sb.is_hijacked(t, a or {}, spec, r) for t, a in actions]
        out_rows.append({**r, "prompt": prompt, "replies": replies, "prefill": args.prefill, "model": args.model,
                         "actions": [[t, a] for t, a in actions],
                         "follow_rate": float(np.mean(follows))})
        if i % 10 == 0 or args.pilot:
            el = time.time() - t0
            print(f"[{i + 1}/{len(rows)}] {r['vector']:<11} t={r['template']} "
                  f"follow={np.mean(follows):.2f}  first={actions[0][0]} "
                  f"({el / (i + 1):.1f}s/prompt, eta {el / (i + 1) * (len(rows) - i - 1) / 60:.0f}m)",
                  flush=True)

    with open(OUT / f"{tag}decisions.jsonl", "w") as f:
        for r in out_rows:
            f.write(json.dumps(r) + "\n")

    print("activations...", flush=True)
    acts = lm.get_activations(model, tok, lm.as_chat(tok, [r["prompt"] for r in out_rows]),
                              batch_size=4)
    np.save(OUT / f"{tag}acts.npy", acts.astype(np.float16))
    print("acts", acts.shape)

    for v in ("clean", "description", "output"):
        fr = [r["follow_rate"] for r in out_rows if r["vector"] == v]
        if fr:
            print(f"{v:<12} n={len(fr):<4} mean follow_rate={np.mean(fr):.2f}  "
                  f"prompts with any follow={np.mean([x > 0 for x in fr]):.2f}")
    print(f"total {(time.time() - t0) / 60:.1f} min")


if __name__ == "__main__":
    main()
