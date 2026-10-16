#!/bin/bash
# Batch version of run_all.sh — survives a dropped SSH connection.
#   cd ~/AI_Hackathon_UVA && sbatch experiments/mcp_guard/rivanna_job.slurm
#   squeue -u $USER                 # check it's running
#   tail -f mcp_guard_<jobid>.out   # watch progress
#SBATCH -A ai-safety-hackathon-rig
#SBATCH -p gpu
#SBATCH --gres=gpu:a100:1
#SBATCH --time=02:00:00
#SBATCH --nodes=1
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=8
#SBATCH --mem=64G
#SBATCH -o mcp_guard_%j.out

module load miniforge
source /scratch/$USER/mcpvenv/bin/activate
bash experiments/mcp_guard/run_all.sh ${MODEL:-Qwen/Qwen2.5-3B-Instruct}
