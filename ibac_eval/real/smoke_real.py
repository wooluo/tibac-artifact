"""One verbose trial for manual inspection: python3 smoke_real.py A-quiet B0"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))
from ibac_eval.real.llm_client import LLMClient
from ibac_eval.real.llm_agent import run_real_trial

sid, cfg = sys.argv[1], sys.argv[2]
trial = int(sys.argv[3]) if len(sys.argv) > 3 else 0
r = run_real_trial(LLMClient(), sid, cfg, trial)
for k, v in r.items():
    if k != "abandonment":
        print(f"{k}: {v}")
print("denied:", r["abandonment"])
