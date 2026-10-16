"""Load KEY=VALUE lines from the repo-root .env into os.environ (never prints values)."""
import os
from pathlib import Path


def load_env(path=Path(__file__).resolve().parents[2] / ".env"):
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
