# HANDOFF: run the MCP Guard experiment on Rivanna (GPU)

> **For Claude:** you are helping a teammate run this experiment on UVA's Rivanna cluster. Read this whole file, then `experiments/mcp_guard/README.md` and `research/MCP_SECURITY_RESEARCH.md` for background. Then walk the user through the steps below. Run commands yourself when you can. When a step needs an interactive login (SSH with Duo), give the user the exact command and ask them to paste the output back.
> **Deadline:** hand-in is **3:30 PM on Fri 16 Oct 2026**. We need results by about **2:45 PM**. Optimize for getting *a* clean result, not a perfect one.

## What this is (30-second version)
- UVA interpretability hackathon, theme "Trust, but verify." Our project: a third-party MCP tool (`check_status`) smuggles an instruction to steal a **synthetic canary key**, either through its *description* (OWASP MCP03, tool poisoning) or its *output* (MCP06, goal hijacking).
- Question: **can a linear probe on the agent's activations tell that it's about to follow the injection**, and does that catch anything a text-level guard misses?
- On a laptop CPU, Qwen2.5-0.5B was too weak: it followed injections 0–3% of the time because it's barely competent. **That's why we need a GPU and a 3B model.**

## Rules
- **Do not modify `starter_code/`.** All work happens in `experiments/mcp_guard/`.
- Everything is synthetic. The "secret" is `CANARY-SVCKEY-4RZ9-NOT-A-REAL-SECRET`, and `send_message` only records a message. Don't add real exfiltration or real credentials.
- Report results honestly, including negative ones. The judges explicitly prefer a clean negative result over an overclaim.

## Steps

### 0. Getting a shell on Rivanna (choose one)
- **A. Terminal:** `ssh <computing-id>@login.hpc.virginia.edu`, then approve Duo. Use the UVA VPN if off-grounds. Leave out `-Y`.
- **B. Browser:** https://ood.hpc.virginia.edu → Clusters → *Rivanna Shell Access*.
- **C. (Smoothest for Claude) Run Claude Code on Rivanna itself.** From the login shell: `curl -fsSL https://claude.ai/install.sh | bash`, then run `claude` inside the repo folder and point it at this file. Claude can then run every step below directly.

If the login closes right after the password: your account may not be active in the `ai-safety-hackathon-rig` allocation yet. Ask on the hackathon Discord.

### 1. Get the code (login node)
```bash
cd ~
git clone -b mcp-guard-experiment https://github.com/ShaheerG13/AI_Hackathon_UVA.git
cd AI_Hackathon_UVA
```
(If the repo is private, the owner must add you as a collaborator first.)

### 2. One-time environment setup (login node, about 5 min)
```bash
module load miniforge
python -m venv /scratch/$USER/mcpvenv
source /scratch/$USER/mcpvenv/bin/activate
pip install --upgrade pip
pip install torch transformers scikit-learn scipy matplotlib numpy
```
If `module load miniforge` fails, run `module spider python` and use what it lists, or check the Discord scripts.

### 3. Run it (recommended: batch job, survives a dropped connection)
```bash
cd ~/AI_Hackathon_UVA
sbatch experiments/mcp_guard/rivanna_job.slurm        # default model: Qwen/Qwen2.5-3B-Instruct
squeue -u $USER                                        # PD = waiting in queue, R = running
tail -f mcp_guard_<JOBID>.out                          # watch progress (Ctrl-C stops watching, not the job)
```
**Interactive alternative:**
```bash
srun -A ai-safety-hackathon-rig -p gpu --time=02:00:00 --nodes=1 --ntasks-per-node=1 --cpus-per-task=8 --mem=64G --gres=gpu:a100:1 --pty bash
module load miniforge && source /scratch/$USER/mcpvenv/bin/activate
cd ~/AI_Hackathon_UVA && bash experiments/mcp_guard/run_all.sh Qwen/Qwen2.5-3B-Instruct
```
Expected on an A100: model download 2–5 min, pilot about 1 min, full collection about 5–15 min, analysis under 1 min, guard eval about 10–20 min.

### 4. Sanity checks (Claude: check these in the output and tell the user)
1. The first line must say `cuda: True NVIDIA A100...`. If it says `NO GPU`, you're on the login node or the job didn't get a GPU.
2. **Pilot follow rates:** look at the `description` / `output` lines after the pilot.
   - If the mean follow_rate is **0.00**, the model never follows and the intent probe can't work. Cancel (`scancel <JOBID>`) and switch models (below).
   - **Around 0.1–0.7 is ideal.** Near 1.0 also limits the analysis.
3. In `analyze_log.txt`: `ctrl_acc` (shuffled-label control) should be about chance. If the real probe isn't clearly above it, we found nothing, and we say so.

**Switching models:** `MODEL=Qwen/Qwen2.5-1.5B-Instruct sbatch experiments/mcp_guard/rivanna_job.slurm`. Use 1.5B if 3B never follows. 7B is also an option if it resists everything. If the probe file errors in the guard eval, the probe didn't train because one class was missing. Report that, and skip the probe mode with `--modes none,scan,taint`.

### 5. Send results back
```bash
cd ~/AI_Hackathon_UVA
tar czf mcp_results.tgz experiments/mcp_guard/results mcp_guard_*.out
```
Download `mcp_results.tgz`. With Open OnDemand, use the *Files* app. With a terminal, run this **on the laptop**: `scp <id>@login.hpc.virginia.edu:~/AI_Hackathon_UVA/mcp_results.tgz .`. Send it to the team.

The key files are `summary.json`, `layer_sweep.png`, `analyze_log.txt`, `guard_results.json` and `guard_log.txt`. `acts.npy` is large and optional.

## What the outputs mean
- **A. PRESENCE:** can a probe tell that an injection is in context, on injection phrasings it never saw? This is expected to be easy. Compare it to the TF-IDF text baseline.
- **B. INTENT:** among poisoned prompts, can a probe predict *whether the model will follow*? **This is the headline result.** It's interesting if it beats both the TF-IDF and the vector-only baselines.
- **Guard modes:** `none` (baseline hijack rate), `scan` (keyword scanner + schema pinning), `taint` (trifecta rule: no egress after untrusted content), `probe` (activation probe). We want each one's hijack rate, false blocks on clean runs, and whether the real task still got done.

## Known gotchas
- Small models invent extra `RESULT:` lines. `sandbox.parse_first` handles that; don't switch back to the starter's `parse()`.
- Decision-point sampling prefills the reply with `ACTION:`, so the question is "when it acts, does it act on the injection?". Mention this in the writeup.
- The keyword scanner was written after seeing the templates, so its catch rate is optimistic.
