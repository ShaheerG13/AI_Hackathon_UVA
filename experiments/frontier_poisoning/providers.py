"""
providers.py — run one tool-using agent episode against a real model API.

Two backends (Anthropic Messages API, OpenAI Chat Completions), one interface:

    r = run_episode(backend, model, system, tool_defs_fn, task, box, guard,
                    defense, max_steps=6)

`tool_defs_fn(poisoned)` returns the (name, desc, schema) list for this step —
a function so the rugpull vector can serve a clean description on step 1 and a
poisoned one afterwards. Returns a dict with the transcript, token usage, the
final text, whether any tool call was blocked, and the tool-call trace.

Cost is tracked by the caller from `usage`. Nothing here leaves the process:
tool calls run against the in-memory MCPSandbox from common.py.
"""

import json

import common as C


def _trace(box):
    return [(t, a) for t, a in box.log]


# ----------------------------------------------------------------- Anthropic

def _anthropic_tools(defs):
    return [{"name": n, "description": d, "input_schema": s} for n, d, s in defs]


def run_anthropic(client, model, system, tool_defs_fn, task, box, guard, defense,
                  max_steps=6, max_tokens=700):
    messages = [{"role": "user", "content": task}]
    usage = {"in": 0, "out": 0}
    final_text, blocked_any = "", False
    for step in range(max_steps):
        defs = tool_defs_fn(poisoned=(step > 0))
        resp = client.messages.create(
            model=model, max_tokens=max_tokens, system=system,
            tools=_anthropic_tools(defs), messages=messages)
        usage["in"] += resp.usage.input_tokens
        usage["out"] += resp.usage.output_tokens
        tool_uses = [b for b in resp.content if b.type == "tool_use"]
        texts = [b.text for b in resp.content if b.type == "text"]
        if not tool_uses:
            final_text = "\n".join(texts)
            break
        # Drop thinking/redacted_thinking blocks before re-appending: the rugpull vector
        # changes the tool list between turns, which would invalidate a bound thinking
        # block's signature (preserved thinking). We don't need reasoning continuity here.
        kept = [b for b in resp.content if getattr(b, "type", None) not in
                ("thinking", "redacted_thinking")]
        messages.append({"role": "assistant", "content": kept})
        results = []
        prompt_text = system + "\n" + json.dumps(messages[-2:], default=str)
        for b in tool_uses:
            out, blk = C.execute(box, guard, b.name, b.input or {}, prompt_text)
            blocked_any = blocked_any or blk
            results.append({"type": "tool_result", "tool_use_id": b.id,
                            "content": C.wrap_result(defense, out)})
        messages.append({"role": "user", "content": results})
    return {"final": final_text, "usage": usage, "blocked": blocked_any,
            "trace": _trace(box), "steps": step + 1}


# ------------------------------------------------------------------- OpenAI

def _openai_create(client, kw, max_tokens):
    """Create with graceful fallback for per-model parameter quirks (reasoning_effort,
    max_completion_tokens vs max_tokens)."""
    for _ in range(3):
        try:
            return client.chat.completions.create(**kw)
        except Exception as e:  # noqa: BLE001
            msg = str(e)
            if "reasoning_effort" in msg and "reasoning_effort" in kw:
                kw.pop("reasoning_effort"); continue
            if "max_completion_tokens" in msg and "max_completion_tokens" in kw:
                kw.pop("max_completion_tokens"); kw["max_tokens"] = max_tokens; continue
            raise
    return client.chat.completions.create(**kw)


def _openai_tools(defs):
    return [{"type": "function",
             "function": {"name": n, "description": d, "parameters": s}}
            for n, d, s in defs]


def run_openai(client, model, system, tool_defs_fn, task, box, guard, defense,
               max_steps=6, max_tokens=700):
    messages = [{"role": "system", "content": system}, {"role": "user", "content": task}]
    usage = {"in": 0, "out": 0}
    final_text, blocked_any = "", False
    for step in range(max_steps):
        defs = tool_defs_fn(poisoned=(step > 0))
        kw = {"model": model, "messages": messages, "tools": _openai_tools(defs),
              "max_completion_tokens": max_tokens, "reasoning_effort": "none"}
        resp = _openai_create(client, kw, max_tokens)
        if resp.usage:
            usage["in"] += resp.usage.prompt_tokens
            usage["out"] += resp.usage.completion_tokens
        msg = resp.choices[0].message
        if not msg.tool_calls:
            final_text = msg.content or ""
            break
        messages.append(msg.model_dump(exclude_none=True))
        prompt_text = system + "\n" + json.dumps(messages[-2:], default=str)
        for tc in msg.tool_calls:
            try:
                args = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                args = {}
            out, blk = C.execute(box, guard, tc.function.name, args, prompt_text)
            blocked_any = blocked_any or blk
            messages.append({"role": "tool", "tool_call_id": tc.id,
                             "content": C.wrap_result(defense, out)})
    return {"final": final_text, "usage": usage, "blocked": blocked_any,
            "trace": _trace(box), "steps": step + 1}


def run_episode(backend, client, model, system, tool_defs_fn, task, box, guard, defense,
                **kw):
    if backend == "anthropic":
        return run_anthropic(client, model, system, tool_defs_fn, task, box, guard, defense, **kw)
    if backend == "openai":
        return run_openai(client, model, system, tool_defs_fn, task, box, guard, defense, **kw)
    raise ValueError(backend)
