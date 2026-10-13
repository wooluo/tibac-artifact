# TIBAC Artifact Repository

Code, formal models, raw data, and audits for
*"Task-Intent Bound Access Control with Verifiable Runtime Enforcement for
Autonomous Agents"*.

Evidence layers and one-command reproduction — see **[REPRODUCING.md](REPRODUCING.md)**:

| Layer | What | Run |
| --- | --- | --- |
| Formal verification | 5 security properties, exhaustive explicit-state model checking (two-level delegation, TOCTOU races, revocation cascade), ablation counterexamples | `python3 formal/verify.py` |
| Mechanism-level simulation | B0–B4 comparison, 10 attack scenarios + 11 legitimate tasks, 55,800 trials, H1–H5 | `python3 ibac_eval/run_experiments.py` (~50 s, deterministic) |
| Reference engine | HMAC capability-token policy engine + latency benchmark | `python3 prototype/tibac_engine.py && python3 prototype/bench_overhead.py` |
| Real-LLM experiments | glm-4-flash agent loop over the same contracts/planes/metrics; 475 archived trials | `python3 ibac_eval/real/run_real.py --trials 5` |
| Audit | 53 automated checks recomputing every paper claim from artifacts | `python3 audit/check_paper_claims.py` |

Zero third-party dependencies for simulation, verification, and engine
(Python ≥3.10 standard library). Related-work positioning: `related_work.md`.
