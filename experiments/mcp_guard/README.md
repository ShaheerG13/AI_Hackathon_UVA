# MCP Guard experiment

**Question:** when a third-party MCP tool smuggles an instruction into an agent's context (through its description, OWASP MCP03, or through its output, MCP06), can we tell from the model's activations that it is about to follow the instruction? And does that signal catch anything a text-level guard misses?

Self-contained copy. Nothing in `starter_code/` is modified.

| File | What it is |
|---|---|
| `lm.py`, `probes.py` | Copied from the starter. `lm.py` changes: Qwen2.5-0.5B default, `sample()` for batched sampling, and `get_activations` max_length raised from 256 to 2048 (prompts are long) |
| `sandbox.py` | Copied from the starter, plus an appended `mcp_guard extensions` section: the `check_status` third-party tool, poisoning conditions, decision-point prompts, `run_agent_mcp` with a guard hook |
| `make_scenario.py` → `scenarios/mcp_poisoning.json` | Starter files/framings + 12 injection templates (4 held out), 5 tasks, benign control notes |
| `collect.py` | Decision-point dataset: k sampled next actions per prompt (follow rate) + activations |
| `analyze.py` | Probes: A = injection present, B = will follow. Held-out templates, shuffled control, TF-IDF text baseline |
| `guard.py` | Middleman: TOFU schema pinning + scanner, trifecta taint policy, activation probe, JSONL audit log |
| `evaluate_guard.py` | Full episodes per guard mode: hijack rate, false blocks, task completion |
| `run_all.sh`, `rivanna_job.slurm` | Run everything (interactive / SLURM batch) |
| `HANDOFF.md` | Step-by-step for a teammate (or their Claude) running on Rivanna |

**Running on Rivanna / a GPU? Start with [`HANDOFF.md`](HANDOFF.md).**

## Run
```bash
# from repo root; venv at .venv
.venv/Scripts/python experiments/mcp_guard/collect.py --pilot
.venv/Scripts/python experiments/mcp_guard/collect.py --addrs 2 --k 4
.venv/Scripts/python experiments/mcp_guard/analyze.py
.venv/Scripts/python experiments/mcp_guard/evaluate_guard.py --n 2
```

Safety: everything is synthetic. The "secret" is the starter's canary string, and `send_message` only records a message.
