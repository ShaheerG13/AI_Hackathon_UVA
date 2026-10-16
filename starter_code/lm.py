"""
lm.py — everything that touches the language model.

    model, tok = load_model()                 # SmolLM2-135M-Instruct by default
    chat(model, tok, "hello")                 # one reply
    acts = get_activations(model, tok, texts) # (n_texts, n_layers + 1, d_model)
    with steer(model, layer, direction, 4.0): ...
    with ablate(model, layer, direction): ...

Layer numbering is the same everywhere in this repo: layer 0 is the token
embeddings, layer k is the residual stream *after* transformer block k.
So `acts[:, k]` and `steer(model, k, ...)` refer to the same place.
"""

from contextlib import contextmanager

import numpy as np
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# The smallest instruct model that still has a chat template and standard
# Llama-style layers. Swap for a bigger one (e.g. Qwen/Qwen2.5-0.5B-Instruct)
# when you need the agent to actually follow instructions.
MODEL_ID = "HuggingFaceTB/SmolLM2-135M-Instruct"


# A larger model the probing literature leans on: Google released sparse
# autoencoders for every layer of it (Gemma Scope), and its 2304-dim residual
# stream gives much cleaner linear probes than tiny models. Gated on Hugging
# Face (accept the license once, then log in) and best on a GPU.
PROBE_MODEL_ID = "google/gemma-2-2b-it"


def load_model(model_id=MODEL_ID):
    tok = AutoTokenizer.from_pretrained(model_id)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    tok.padding_side = "right"          # get_activations relies on this
    model = AutoModelForCausalLM.from_pretrained(model_id)
    if torch.cuda.is_available():       # bfloat16 on GPU halves memory; fine for probing
        model.to("cuda", dtype=torch.bfloat16)
    else:
        model.to("cpu", dtype=torch.float32)
    model.eval()
    return model, tok


def as_chat(tok, texts):
    """Wrap each text as a user message in the model's chat template, ending
    where the model would start replying. Reading activations at that last
    token captures the model's 'how should I answer this?' state — the
    standard place to probe for refusal."""
    return [tok.apply_chat_template([{"role": "user", "content": t}],
                                    tokenize=False, add_generation_prompt=True)
            for t in texts]


def describe(model):
    """Print the numbers you need: layers, width, size."""
    n_params = sum(p.numel() for p in model.parameters())
    print(f"layers: {model.config.num_hidden_layers}   "
          f"d_model: {model.config.hidden_size}   "
          f"params: {n_params / 1e6:.0f}M   device: {model.device}")


def chat(model, tok, message, system=None, max_new_tokens=100, temperature=0.0):
    """Send one chat message, get the reply as text.
    (Gemma's chat template has no system role — leave system=None for Gemma.)"""
    msgs = ([{"role": "system", "content": system}] if system else [])
    msgs.append({"role": "user", "content": message})
    text = tok.apply_chat_template(msgs, tokenize=False, add_generation_prompt=True)
    enc = tok(text, return_tensors="pt").to(model.device)
    with torch.no_grad():
        out = model.generate(
            **enc,
            max_new_tokens=max_new_tokens,
            do_sample=temperature > 0,
            temperature=temperature if temperature > 0 else None,
            top_p=0.95 if temperature > 0 else None,
            pad_token_id=tok.pad_token_id,
        )
    return tok.decode(out[0, enc["input_ids"].shape[1]:], skip_special_tokens=True)


def generator(model, tok, system=None, temperature=0.7, max_new_tokens=80):
    """Wrap chat() as a plain function prompt -> reply. The agent in
    sandbox.py takes one of these. Temperature > 0 so repeated runs differ."""
    def generate(prompt):
        return chat(model, tok, prompt, system=system,
                    max_new_tokens=max_new_tokens, temperature=temperature)
    return generate


def _blocks(model):
    return model.model.layers          # Llama, Qwen, Mistral, SmolLM all use this


def get_activations(model, tok, texts, batch_size=16):
    """
    Residual-stream activations at the LAST real token of each text, at every
    layer. Returns a NumPy array of shape (len(texts), n_layers + 1, d_model).

    How: a forward hook on the embeddings and on each transformer block saves
    that module's output during one ordinary forward pass. (We use our own
    hooks rather than output_hidden_states because those record values before
    other hooks run, which would hide the effect of steer()/ablate().)
    """
    store = {}

    def save(idx):
        def hook(_module, _inputs, output):
            store[idx] = (output[0] if isinstance(output, tuple) else output).detach()
        return hook

    handles = [model.model.embed_tokens.register_forward_hook(save(0))]
    handles += [b.register_forward_hook(save(k + 1)) for k, b in enumerate(_blocks(model))]
    n = len(handles)
    chunks = []
    try:
        for i in range(0, len(texts), batch_size):
            batch = list(texts[i:i + batch_size])
            enc = tok(batch, return_tensors="pt", padding=True, truncation=True,
                      max_length=256).to(model.device)
            with torch.no_grad():
                model(**enc)
            hs = torch.stack([store[k] for k in range(n)], dim=1)   # (B, L+1, T, d)
            last = enc["attention_mask"].sum(dim=1) - 1             # last real token
            picked = hs[torch.arange(hs.shape[0]), :, last]         # (B, L+1, d)
            chunks.append(picked.float().cpu().numpy())
    finally:
        for h in handles:
            h.remove()
    return np.concatenate(chunks, axis=0)


def _unit(direction, like):
    d = torch.as_tensor(np.asarray(direction), dtype=like.dtype, device=like.device)
    return d / (d.norm() + 1e-8)


@contextmanager
def _edit_layer(model, layer, fn):
    """Apply fn(hidden) -> hidden to the residual stream at `layer`."""
    if layer < 1:
        raise ValueError("layer must be >= 1 (layer 0 is the embeddings)")

    def hook(_module, _inputs, output):
        if isinstance(output, tuple):
            return (fn(output[0]),) + output[1:]
        return fn(output)

    handle = _blocks(model)[layer - 1].register_forward_hook(hook)
    try:
        yield
    finally:
        handle.remove()


def steer(model, layer, direction, alpha):
    """Add alpha * unit(direction) to every position at `layer`.
    Use as: `with steer(model, 12, d, 4.0): chat(...)`."""
    def fn(h):
        return h + alpha * _unit(direction, h)
    return _edit_layer(model, layer, fn)


def ablate(model, layer, direction):
    """Remove the component along `direction` at `layer` (projection ablation).
    If behaviour that depended on the direction goes away, it was load-bearing."""
    def fn(h):
        d = _unit(direction, h)
        return h - (h @ d).unsqueeze(-1) * d
    return _edit_layer(model, layer, fn)
