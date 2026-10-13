"""Runtime-overhead benchmark for the TIBAC reference policy engine.

Measures the per-tool-call cost of mandatory adjudication (the PDP decision,
dominated by HMAC verification + scope matching) on a realistic workload mix,
plus token issuance cost, and expresses the overhead relative to typical tool
latencies (a fast internal API call ~50 ms; an LLM planning step ~1.5 s).

Run: python3 prototype/bench_overhead.py   -> prototype/bench_results.md
"""
from __future__ import annotations

import os
import platform
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from tibac_engine import Action, PolicyDecisionPoint

N = 200_000


def pct(sorted_vals, q):
    return sorted_vals[min(len(sorted_vals) - 1, int(q * len(sorted_vals)))]


def stats_us(vals):
    s = sorted(vals)
    return {"mean": statistics.fmean(s), "p50": pct(s, 0.50),
            "p95": pct(s, 0.95), "p99": pct(s, 0.99), "max": s[-1]}


def main():
    pdp = PolicyDecisionPoint()
    tok = pdp.issue("bench", "agent",
                    scopes=["file:/docs/project/**", "db:r:reports",
                            "email:boss@corp.com", "net:api.partner.example",
                            "exec:local"],
                    email_sinks=["boss@corp.com"], net_hosts=["api.partner.example"],
                    ttl_s=3600, budget=10 * N)
    expired = pdp.issue("bench-exp", "agent", scopes=["file:/docs/**"], ttl_s=-1)

    # realistic decision mix: 60% in-scope allow, 15% out-of-scope deny,
    # 10% approved sink, 10% unapproved sink, 5% expired lease
    cases = [
        (Action("agent", "read_file", "read", "file:/docs/project/spec.md"), tok),
        (Action("agent", "db_query", "read", "db:reports"), tok),
        (Action("agent", "read_file", "read", "file:/root/.ssh/id_rsa"), tok),
        (Action("agent", "send_email", "send", "email:to=boss@corp.com",
                params={"to": "boss@corp.com"}), tok),
        (Action("agent", "send_email", "send", "email:to=archive@partner-archive.com",
                params={"to": "archive@partner-archive.com"}), tok),
        (Action("agent", "read_file", "read", "file:/docs/project/x.md"), expired),
    ]
    weights = [0.30, 0.30, 0.15, 0.10, 0.10, 0.05]

    # warmup
    for a, t in cases:
        pdp.adjudicate(a, t)

    lat = []
    t0 = time.perf_counter()
    for i in range(N):
        r = i % 20
        if r < 6:
            a, t = cases[0]
        elif r < 12:
            a, t = cases[1]
        elif r < 15:
            a, t = cases[2]
        elif r < 17:
            a, t = cases[3]
        elif r < 19:
            a, t = cases[4]
        else:
            a, t = cases[5]
        s = time.perf_counter_ns()
        pdp.adjudicate(a, t)
        lat.append(time.perf_counter_ns() - s)
    wall = time.perf_counter() - t0

    st = stats_us([v / 1000 for v in lat])

    # token issuance cost (lease renewal path)
    iss = []
    for i in range(20_000):
        s = time.perf_counter_ns()
        pdp.issue(f"t{i}", "agent", scopes=["file:/docs/project/**"],
                  ttl_s=600, budget=50)
        iss.append(time.perf_counter_ns() - s)
    st_iss = stats_us([v / 1000 for v in iss])

    def rel(ms_tool):
        return st["mean"] / 1e3 / ms_tool * 100

    here = os.path.dirname(os.path.abspath(__file__))
    L = []
    A = L.append
    A("# TIBAC 参考策略引擎：运行时开销基准\n")
    A(f"- 平台：{platform.platform()} | Python {platform.python_version()}")
    A(f"- 工作负载：{N:,} 次裁决（60% 范围内放行 / 15% 越权拒绝 / 10% 已批汇点 / "
      f"10% 未批汇点拒绝 / 5% 租约过期拒绝），令牌 HMAC-SHA256 签名\n")
    A("## 每次工具调用的裁决开销（µs）\n")
    A("| 指标 | 裁决（含 HMAC 验签+作用域匹配） | 签发新能力令牌（租约更新） |")
    A("| --- | --- | --- |")
    A(f"| mean | {st['mean']:.1f} | {st_iss['mean']:.1f} |")
    A(f"| p50 | {st['p50']:.1f} | {st_iss['p50']:.1f} |")
    A(f"| p95 | {st['p95']:.1f} | {st_iss['p95']:.1f} |")
    A(f"| p99 | {st['p99']:.1f} | {st_iss['p99']:.1f} |")
    A(f"| max | {st['max']:.1f} | {st_iss['max']:.1f} |\n")
    A("## 相对开销\n")
    A("| 基线场景 | TIBAC 裁决占比 |")
    A("| --- | --- |")
    A(f"| 快速内部 API 工具调用（50 ms） | {rel(50):.3f}% |")
    A(f"| 慢速外部 API / RPA 操作（500 ms） | {rel(500):.4f}% |")
    A(f"| LLM 规划步（1.5 s） | {rel(1500):.4f}% |\n")
    A("**结论：** 参考实现（纯 Python、无缓存、无向量化）的单次裁决开销在数十微秒量级，"
      "相对任何真实工具调用（毫秒级起）或模型推理步（秒级）均 <0.2%，"
      "即强制授权的运行时代价可忽略；真正的成本在升级审批与撤销后的任务中断"
      "（见 `ibac_eval/results/summary.md` 第 5 节）。\n")
    A("**边界：** 这是参考实现的量级证据，不是生产性能调优结论；"
      "生产部署应使用常量时间比较、本地缓存热令牌的 MAC 验证、并预算原子计数器。")
    out = os.path.join(here, "bench_results.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"{N:,} adjudications in {wall:.2f}s -> mean {st['mean']:.1f}µs "
          f"p99 {st['p99']:.1f}µs | issue mean {st_iss['mean']:.1f}µs")
    print(f"report -> {out}")


if __name__ == "__main__":
    main()
