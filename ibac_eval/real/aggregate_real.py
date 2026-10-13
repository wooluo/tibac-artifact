"""Aggregate real-LLM trial results -> results_real.md (+ aggregate CSVs).

Run on the host after pulling real_trials.csv from the VM:
    scp vm:~/tibac/ibac_eval/real/real_trials.csv ibac_eval/real/
    python3 ibac_eval/real/aggregate_real.py
"""
from __future__ import annotations

import os
import sys

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))


def main():
    frames = [pd.read_csv(os.path.join(HERE, "real_trials.csv"))]
    extra = os.path.join(HERE, "real_trials_extra.csv")
    if os.path.exists(extra):
        frames.append(pd.read_csv(extra))
    df = pd.concat(frames, ignore_index=True)
    atk, leg = df[df["kind"] == "attack"], df[df["kind"] == "legit"]
    L = ["# 真实 LLM 智能体验证结果（glm-4-flash，temperature 0.7）\n"]
    A = L.append
    A(f"- 试验：攻击 {len(atk)} 次（10 场景 × 5 配置 × 5 trials）、"
      f"合法 {len(leg)} 次（11 任务 × 5 配置 × 3 trials）。")
    A("- 与机制级仿真共用世界、任务契约（TAC）、控制面（B0–B4）与指标定义；"
      "唯一区别：决策由真实模型做出，注入是否被采纳由模型行为决定。\n")

    A("## 主结果（聚合全部攻击场景）\n")
    A("| 配置 | 触发率(engaged) | UAR | ABR | 严重泄露率 P(leak) |")
    A("| --- | --- | --- | --- | --- | --- |")
    for cfg in ["B0", "B1", "B2", "B3", "B4", "B4-coarse", "B4-noAtten"]:
        d = atk[(atk["config"] == cfg) & atk["engaged"]]
        if not len(atk[atk["config"] == cfg]):
            continue
        eng = atk[atk["config"] == cfg]["engaged"].mean()
        u = d["uar_frac"].mean() if len(d) else float("nan")
        a = d["abr_frac"].mean() if len(d) else float("nan")
        p = atk[atk["config"] == cfg]["leak"].mean()
        A(f"| {cfg} | {eng:.0%} | {u:.1%} | {a:.1%} | {p:.0%} |")
    A("")
    A("## 合法任务完成率（LCR）\n")
    A("| 配置 | LCR |")
    A("| --- | --- |")
    for cfg in ["B0", "B1", "B2", "B3", "B4"]:
        A(f"| {cfg} | {leg[leg['config'] == cfg]['completed'].mean():.1%} |")
    A("")
    A("## 分场景（B0 vs B4）\n")
    A("| 场景 | B0 UAR | B4 UAR | B4 拒绝原因示例 |")
    A("| --- | --- | --- | --- |")
    for sid in sorted(atk["scenario"].unique()):
        r = []
        for cfg in ["B0", "B4"]:
            d = atk[(atk["scenario"] == sid) & (atk["config"] == cfg) & atk["engaged"]]
            r.append(f"{d['uar_frac'].mean():.0%}" if len(d) else "n/a")
        den = atk[(atk["scenario"] == sid) & (atk["config"] == "B4")]["abandonment"]
        ex = next((x for x in den if isinstance(x, str) and x not in ("[]", "")), "")
        A(f"| {sid} | {r[0]} | {r[1]} | {ex[:80]} |")
    out = os.path.join(HERE, "results_real.md")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"-> {out}")
    print(df[df["kind"] == "attack"].groupby("config")[
        ["uar_frac", "abr_frac"]].mean().round(3))
    print(df[df["kind"] == "legit"].groupby("config")["completed"].mean().round(3))


if __name__ == "__main__":
    main()
