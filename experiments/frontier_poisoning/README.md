# frontier_poisoning — tool poisoning against real Claude / GPT models

Red-teams our OWN synthetic sandbox (canary secret, `send_message` records only,
nothing leaves the process) against live model APIs, and tests two defenses.
Reuses the scenario + MCP Guard from `../mcp_guard` (unmodified).

## Files
| File | Role |
|---|---|
| `envload.py` | load API keys from repo-root `.env` (never printed) |
| `common.py` | scenario, 5 injection vectors (clean/description/schema/result/rugpull), 3 defenses (none/spotlight/guard), weak vs default system prompt |
| `providers.py` | one tool-use agent loop for Anthropic and OpenAI backends |
| `run_experiment.py` | full matrix runner with a **hard spend cap** and cost accounting |
| `demo.py` | the working example: clean vs poisoned report, + defense comparison |
| `RESULTS_frontier.md` | findings |

## Quick start
```bash
# from repo root, venv at .venv, keys in .env (ANTHROPIC_API_KEY, OPENAI_API_KEY,
# ANTHROPIC_WORKSPACE_ID if the key is org-scoped)
.venv/Scripts/python experiments/frontier_poisoning/demo.py gpt-luna 10 --show  # hijack lands ~8/10
.venv/Scripts/python experiments/frontier_poisoning/demo.py haiku 8             # resists 0/10
.venv/Scripts/python experiments/frontier_poisoning/run_experiment.py --pilot   # cost check
```
`demo.py <model> <n> [--show] [--weak] [--single] [--regex]`. Default detector is an
independent gpt-luna judge of the report's stated root cause; `--regex` is a faster
heuristic that over-counts reports which quote the injection to reject it.

## Headline
Frontier models refuse the textbook secret-exfil attack (~0–1%), but GPT-6-luna can be
driven to write an attacker-dictated FALSE root cause into its report ~8/10 of the time
(OWASP MCP06, an integrity attack). Haiku resists and flags the injection. Prompt-level
spotlighting stops it; the trifecta/exfil guard does not (writing the report isn't egress).
Models under test, judge, and spend cap are all configurable. See `RESULTS_frontier.md`.

Safety: synthetic throughout. Defensive measurement of our own sandbox, not an attack on
any real system.
