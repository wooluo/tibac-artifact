"""Real-LLM experiment orchestrator (runs on the VM or anywhere with API access).

Usage:
    python3 run_real.py --trials 5                       # full pilot
    python3 run_real.py --only A-quiet B0 B4 --trials 2  # smoke subset
Resumable: appends to real_trials.csv, skips already-run cells.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))                    # -> ibacsim
sys.path.insert(0, os.path.dirname(os.path.dirname(_HERE)))   # -> ibac_eval pkg
from ibac_eval.real.llm_client import LLMClient
from ibac_eval.real.llm_agent import run_real_trial
from ibacsim.scenarios import ATTACK_SCENARIOS, LEGIT_SCENARIOS

HERE = os.path.dirname(os.path.abspath(__file__))
FIELDS = ["config", "scenario", "kind", "trial", "model", "attempts_u",
          "blocked_u", "executed_u", "executed_severe_u", "inconclusive_u",
          "uar_frac", "abr_frac", "leak", "engaged", "escalations",
          "escalations_approved", "rounds", "completed", "abandonment"]
_print_lock = threading.Lock()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5)
    ap.add_argument("--only", nargs="*", default=None,
                    help="filters like A-quiet B0 B4 (scenario or config ids)")
    ap.add_argument("--model", default=os.environ.get("GLM_MODEL", "glm-4-flash"))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--legit-trials", type=int, default=3)
    ap.add_argument("--out", default=os.path.join(HERE, "real_trials.csv"))
    args = ap.parse_args()

    done = set()
    if os.path.exists(args.out):
        with open(args.out) as f:
            for r in csv.DictReader(f):
                done.add((r["config"], r["scenario"], int(r["trial"])))

    cells = []
    cfgs = ["B0", "B1", "B2", "B3", "B4"]
    if not args.only or any(c in args.only for c in ("B4-coarse", "B4-noAtten")):
        cfgs += ["B4-coarse", "B4-noAtten"]
    for sc in ATTACK_SCENARIOS:
        for cfg in cfgs:
            for t in range(args.trials):
                cells.append((cfg, sc.sid, t, sc.kind))
    for sc in LEGIT_SCENARIOS:
        for cfg in ["B0", "B1", "B2", "B3", "B4"]:
            for t in range(args.legit_trials):
                cells.append((cfg, sc.sid, t, sc.kind))
    if args.only:
        cells = [c for c in cells if c[0] in args.only or c[1] in args.only]
    cells = [c for c in cells if (c[0], c[1], c[2]) not in done]
    print(f"{len(cells)} trials to run (model={args.model}, workers={args.workers})",
          flush=True)

    client = LLMClient(model=args.model)
    t0 = time.time()

    def work(cell):
        cfg, sid, t, kind = cell
        c = LLMClient(model=args.model)
        r = run_real_trial(c, sid, cfg, t)
        return r

    with open(args.out, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        if not os.path.getsize(args.out):
            w.writeheader()
        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = {ex.submit(work, c): c for c in cells}
            n = 0
            for fut in as_completed(futs):
                r = fut.result()
                with _print_lock:
                    w.writerow({k: (json.dumps(v, ensure_ascii=False)
                                    if isinstance(v, list) else v)
                                for k, v in r.items()})
                    f.flush()
                    n += 1
                    if n % 10 == 0 or n == len(cells):
                        print(f"  {n}/{len(cells)} done "
                              f"({time.time() - t0:.0f}s)", flush=True)
    print(f"ALL DONE in {time.time() - t0:.0f}s -> {args.out}", flush=True)


if __name__ == "__main__":
    main()
