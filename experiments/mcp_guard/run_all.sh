#!/bin/bash
# Run the whole MCP Guard experiment (Rivanna GPU node or any CUDA machine).
#   bash experiments/mcp_guard/run_all.sh Qwen/Qwen2.5-3B-Instruct
# Run from the repo root. Results go to experiments/mcp_guard/results/.
set -e
MODEL=${1:-Qwen/Qwen2.5-3B-Instruct}
D=experiments/mcp_guard
if [ -d /scratch/$USER ]; then export HF_HOME=${HF_HOME:-/scratch/$USER/hf}; fi   # Rivanna: keep downloads off home quota
python -c "import torch; print('cuda:', torch.cuda.is_available(), torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'NO GPU - stop and fix')"
python -u $D/collect.py --pilot --model $MODEL
python -u $D/collect.py --addrs 2 --k 4 --model $MODEL
python -u $D/analyze.py | tee $D/results/analyze_log.txt
python -u $D/evaluate_guard.py --n 2 --model $MODEL | tee $D/results/guard_log.txt
echo "DONE. Results in $D/results/"
