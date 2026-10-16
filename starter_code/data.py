"""
data.py — the datasets this starter uses.

JailbreakBench JBB-Behaviors — notebook 01 (concepts on real safety data).
    See load_harmful_benign() below.

deepset/prompt-injections (Hugging Face, Apache-2.0) — notebooks 02–04
    662 prompts, each labelled 0 = ordinary request, 1 = prompt injection
    (text trying to override the instructions an LLM was given).
    Splits: train (546) and test (116). Mostly English, some German.

Why this one: it's small enough to run on a laptop, it's labelled, and it's a
genuine cyber-safety concept that is *defensive* to study — the question is
whether a model's activations reveal "someone is trying to hijack my
instructions", which is the same kind of question as "do I think I'm in a
sandbox?". The probing skills transfer directly to the hackathon problem.

    texts, labels = load_injections("train")
"""

import numpy as np

DATASET_ID = "deepset/prompt-injections"
JBB_ID = "JailbreakBench/JBB-Behaviors"


def load_injections(split="train"):
    from datasets import load_dataset          # imported here so the rest of the repo works without it
    ds = load_dataset(DATASET_ID, split=split)
    return list(ds["text"]), np.asarray(ds["label"], dtype=int)


def load_harmful_benign(test_frac=0.3, seed=0):
    """
    JailbreakBench JBB-Behaviors (MIT): 100 harmful requests, each paired with
    a topic-matched benign request, across 10 categories (incl. Malware/Hacking).
    Label 1 = harmful, 0 = benign. Used in notebook 01.

    The split holds out whole TOPICS: a harmful request and its benign twin
    always land on the same side, so the test set asks about topics the probe
    never saw. Returns a dict of lists/arrays.
    """
    from datasets import load_dataset
    ds = load_dataset(JBB_ID, "behaviors")
    rows = [(r["Goal"], 1, r["Behavior"], r["Category"]) for r in ds["harmful"]] + \
           [(r["Goal"], 0, r["Behavior"], r["Category"]) for r in ds["benign"]]
    return split_by_topic(rows, test_frac, seed)


def split_by_topic(rows, test_frac=0.3, seed=0):
    """rows: (text, label, topic, category). Every row of a topic goes to the same side."""
    topics = sorted({r[2] for r in rows})
    rng = np.random.default_rng(seed)
    rng.shuffle(topics)
    test_topics = set(topics[:int(round(len(topics) * test_frac))])
    train = [r for r in rows if r[2] not in test_topics]
    test = [r for r in rows if r[2] in test_topics]
    return {
        "train_texts": [r[0] for r in train], "train_y": np.array([r[1] for r in train]),
        "test_texts": [r[0] for r in test], "test_y": np.array([r[1] for r in test]),
        "train_category": [r[3] for r in train], "test_category": [r[3] for r in test],
    }
