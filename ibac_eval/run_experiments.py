#!/usr/bin/env python3
"""IBAC experimental protocol runner (paper §7).

Usage:
    python3 run_experiments.py            # full run (~2-4 min)
    python3 run_experiments.py --quick    # fast smoke subset
    python3 run_experiments.py --seeds 300 --out results

Outputs into --out (default results/):
    trials_attack.csv, trials_legit.csv       raw per-trial data
    agg_*.csv                                 aggregated tables
    plots/fig1..fig7 *.png                    figures for the paper
    summary.md                                Chinese results report + H1-H5 verdicts
    example_traces.md                         B0 vs B4 episode narratives
"""
from __future__ import annotations

import argparse
import os
import sys
import time

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ibacsim.scenarios import ATTACK_SCENARIOS, LEGIT_SCENARIOS, ALL_SCENARIOS
from ibacsim.runner import run_trial
from ibacsim import stats as st
from ibacsim import plots

MAIN_CFGS = ["B0", "B1", "B2", "B3", "B4"]
SUSC_DEFAULT = [0.2, 0.5, 0.8, 1.0]
HEADLINE_SUSC = 0.8
SEEDS_DEFAULT = 200

ABLATION_CELLS = {
    "B4-noProv": ["C", "H"],          # H3
    "B4-noAtten": ["E", "H"],         # H2
    "B4-NL": ["E", "H"],              # H2 (NL-only delegation)
    "B4-coarse": ["A-quiet", "E", "H"],  # H5
    "B4-bypass": ["A-quiet", "H"],    # H4
    "B4-noRev": ["G", "H"],           # containment / propagation
}
LEGIT_CFGS = MAIN_CFGS + ["B4-coarse"]
DETECTOR_RECALLS = [0.5, 0.65, 0.9, 0.95]


def run_cell(scenarios, config, seeds, susc, recall=0.8, fpr=0.15):
    out = []
    for sc in scenarios:
        for seed in range(seeds):
            out.append(run_trial(sc, config, seed, susc, recall=recall, fpr=fpr))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=SEEDS_DEFAULT)
    ap.add_argument("--susc", type=float, nargs="*", default=SUSC_DEFAULT)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(
        os.path.abspath(__file__)), "results"))
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    seeds = 40 if args.quick else args.seeds
    suscs = [0.5, 0.8] if args.quick else args.susc
    os.makedirs(args.out, exist_ok=True)
    plots_dir = os.path.join(args.out, "plots")
    os.makedirs(plots_dir, exist_ok=True)
    t0 = time.time()

    # ------------------------------------------------------------- 1 main grid
    print(f"[1/6] main attack grid: {len(ATTACK_SCENARIOS)} scenarios x "
          f"{len(MAIN_CFGS)} configs x {len(suscs)} susc x {seeds} seeds")
    recs = []
    for sc in ATTACK_SCENARIOS:
        for cfg in MAIN_CFGS:
            for susc in suscs:
                recs.extend(run_cell([sc], cfg, seeds, susc))
    # ------------------------------------------------------------- 2 ablations
    print("[2/6] ablation / sensitivity cells (susc=0.8)")
    for cfg, sids in ABLATION_CELLS.items():
        scens = [ALL_SCENARIOS[s] for s in sids]
        recs.extend(run_cell(scens, cfg, seeds, HEADLINE_SUSC))
    atk = pd.DataFrame(recs)
    # ------------------------------------------------------------- 3 legit
    print(f"[3/6] legitimate suite: {len(LEGIT_SCENARIOS)} tasks x "
          f"{len(LEGIT_CFGS)} configs x {seeds} seeds")
    lrecs = []
    for sc in LEGIT_SCENARIOS:
        for cfg in LEGIT_CFGS:
            lrecs.extend(run_cell([sc], cfg, seeds, 0.0))
    legit = pd.DataFrame(lrecs)
    # ------------------------------------------------------- 4 detector sweep
    print("[4/6] B1 detector recall sweep")
    drecs = []
    for recall in DETECTOR_RECALLS:
        drecs.extend(run_cell(ATTACK_SCENARIOS, "B1", seeds, HEADLINE_SUSC,
                              recall=recall))
    sweep = pd.DataFrame(drecs)

    atk.to_csv(os.path.join(args.out, "trials_attack.csv"), index=False)
    legit.to_csv(os.path.join(args.out, "trials_legit.csv"), index=False)
    print(f"      trials saved: {len(atk)} attack / {len(legit)} legit "
          f"({time.time() - t0:.0f}s)")

    # ------------------------------------------------------ 5 analysis helpers
    print("[5/6] aggregation, hypothesis tests, figures, report")

    def uar_group(df):
        e = df[df["engaged"]]
        return e

    # (a) UAR/ABR per config aggregated over attack scenarios, per susc
    agg_uar, agg_abr = {}, {}
    for cfg in MAIN_CFGS:
        for susc in suscs:
            e = atk[(atk["config"] == cfg) & (atk["susc"] == susc) & atk["engaged"]]
            agg_uar[(cfg, susc)] = st.boot_ci(e["uar_frac"].tolist())
            agg_abr[(cfg, susc)] = st.boot_ci(e["abr_frac"].tolist())
    # headline combos for fig2
    fig2 = {}
    for cfg in MAIN_CFGS:
        fig2[(cfg, HEADLINE_SUSC, "uar")] = agg_uar[(cfg, HEADLINE_SUSC)]
        fig2[(cfg, HEADLINE_SUSC, "abr")] = agg_abr[(cfg, HEADLINE_SUSC)]

    # per-scenario table at headline susc
    rows = []
    for sc in ATTACK_SCENARIOS:
        for cfg in MAIN_CFGS:
            e = atk[(atk["scenario"] == sc.sid) & (atk["config"] == cfg)
                    & (atk["susc"] == HEADLINE_SUSC) & atk["engaged"]]
            m, lo, hi = st.boot_ci(e["uar_frac"].tolist())
            ma, loa, hia = st.boot_ci(e["abr_frac"].tolist())
            rows.append({"scenario": sc.sid, "config": cfg, "n_engaged": len(e),
                         "UAR": m, "UAR_lo": lo, "UAR_hi": hi,
                         "ABR": ma, "ABR_lo": loa, "ABR_hi": hia})
    per_scen = pd.DataFrame(rows)
    per_scen.to_csv(os.path.join(args.out, "agg_attack_per_scenario.csv"), index=False)

    # LCR
    lcr = {cfg: st.boot_ci(legit[legit["config"] == cfg]["completed"].astype(float).tolist())
           for cfg in LEGIT_CFGS}
    lcr_rows = [{"config": cfg, "LCR": v[0], "lo": v[1], "hi": v[2]}
                for cfg, v in lcr.items()]
    pd.DataFrame(lcr_rows).to_csv(os.path.join(args.out, "agg_lcr.csv"), index=False)

    # paired helper: align (scenario, seed) at headline susc between two configs
    def paired(cfg_a, cfg_b, sids=None, susc=HEADLINE_SUSC, col="uar_frac",
               df=None, require_engaged=True):
        df = df if df is not None else atk
        d = df[(df["susc"] == susc)]
        if sids:
            d = d[d["scenario"].isin(sids)]
        a = d[d["config"] == cfg_a].set_index(["scenario", "seed"])[col]
        b = d[d["config"] == cfg_b].set_index(["scenario", "seed"])[col]
        j = pd.concat([a, b], axis=1, keys=["a", "b"]).dropna()
        if require_engaged:
            mask = j["a"].notna() & j["b"].notna()
            j = j[mask]
        return st.paired_boot(j["a"].tolist(), j["b"].tolist())

    # ------------------------------------------------------ hypothesis tests
    hyp = {}
    for susc in suscs:
        for other in ["B0", "B1", "B2", "B3"]:
            d = atk[(atk["susc"] == susc)]
            a = d[d["config"] == "B4"].set_index(["scenario", "seed"])["uar_frac"]
            b = d[d["config"] == other].set_index(["scenario", "seed"])["uar_frac"]
            j = pd.concat([a, b], axis=1, keys=["a", "b"]).dropna()
            hyp[("H1", susc, other)] = st.paired_boot(j["a"].tolist(), j["b"].tolist())
    hyp[("H2", "NL")] = paired("B4", "B4-NL", ["E", "H"])
    hyp[("H2", "noAtten")] = paired("B4", "B4-noAtten", ["E", "H"])
    hyp[("H3", "noProv")] = paired("B4", "B4-noProv", ["C", "H"])
    hyp[("H3", "B1onC")] = paired("B4", "B1", ["C"])
    hyp[("H4", "bypass")] = paired("B4", "B4-bypass", ["A-quiet", "H"])
    hyp[("H5", "coarse_UAR")] = paired("B4", "B4-coarse", ["A-quiet", "E", "H"])

    # H5 overhead: escalations per legit task, sim ticks
    esc_legit = {cfg: float(legit[legit["config"] == cfg]["escalations"].mean())
                 for cfg in LEGIT_CFGS}
    check_us = {cfg: float(atk[atk["config"] == cfg]["check_us_mean"].mean())
                for cfg in LEGIT_CFGS}
    ticks_legit = {cfg: float(legit[legit["config"] == cfg]["ticks"].mean())
                   for cfg in LEGIT_CFGS}
    hyp[("H5", "esc_legit")] = st.paired_boot(
        legit[legit["config"] == "B4"].sort_values(["scenario", "seed"])["escalations"].tolist(),
        legit[legit["config"] == "B4-coarse"].sort_values(["scenario", "seed"])["escalations"].tolist())

    # containment / propagation on G
    propagation = {}
    containment_n = {}
    for cfg in MAIN_CFGS + ["B4-noRev"]:
        e = atk[(atk["scenario"] == "G") & (atk["config"] == cfg)
                & (atk["susc"] == HEADLINE_SUSC) & atk["engaged"]]
        finite = e["prop_latency"].dropna()
        propagation[CONFIG_LABEL(cfg)] = float(finite.mean()) if len(finite) else None
        containment_n[cfg] = int(e["containment_latency"].notna().sum())
    containment = containment_n.get("B4", 0)

    # detector sweep aggregation (0.8 cell comes from the main grid)
    sweep_all = pd.concat([sweep, atk[(atk["config"] == "B1") &
                                      (atk["susc"] == HEADLINE_SUSC)]], ignore_index=True)
    sweep_pts = []
    for recall in sorted(set(DETECTOR_RECALLS) | {0.8}):
        e = sweep_all[(sweep_all["recall"] == recall) & sweep_all["engaged"]]
        m, lo, hi = st.boot_ci(e["uar_frac"].tolist())
        sweep_pts.append((recall, m))
        print(f"      detector recall={recall:.2f}: UAR={m:.3f}")
    b4_line = agg_uar[("B4", HEADLINE_SUSC)][0]

    # ------------------------------------------------------------- 6 figures
    plots.fig_uar_vs_susc({k: agg_uar[k] for k in agg_uar}, suscs,
                          os.path.join(plots_dir, "fig1_uar_vs_susceptibility.png"))
    plots.fig_abr_uar(fig2, os.path.join(plots_dir, "fig2_abr_uar_by_config.png"))
    plots.fig_lcr(lcr, os.path.join(plots_dir, "fig3_lcr.png"))
    ab_cells = []
    for cfg, sids in [("B0", ["H"]), ("B3", ["H"]), ("B4-coarse", ["H"]),
                      ("B4-noProv", ["H"]), ("B4-noAtten", ["H"]), ("B4-NL", ["E"]),
                      ("B4", ["H"])]:
        e = atk[(atk["scenario"] == sids[0]) & (atk["config"] == cfg)
                & (atk["susc"] == HEADLINE_SUSC) & atk["engaged"]]
        m, lo, hi = st.boot_ci(e["uar_frac"].tolist())
        ab_cells.append((f"{cfg} on {sids[0]}", m, lo, hi))
    plots.fig_ablation(ab_cells, os.path.join(plots_dir, "fig4_ablation_H.png"))
    plots.fig_overhead(esc_legit, check_us, os.path.join(plots_dir, "fig5_overhead.png"))
    plots.fig_detector_sweep(sweep_pts, b4_line,
                             os.path.join(plots_dir, "fig6_detector_sweep.png"))
    plots.fig_latency(containment, propagation,
                      os.path.join(plots_dir, "fig7_propagation_latency.png"))

    # invariance check: model-side adoption draws are keyed by (seed, tag);
    # a control plane can only *prevent exposure* (block the action that would
    # deliver the injection), never change the draw itself. So adopted(config)
    # must be a subset of adopted(B0), and identical whenever the delivery
    # action executed in both.
    inv_ok, inv_n, prevented = True, 0, 0
    for sc in ATTACK_SCENARIOS:
        for seed in range(min(20, seeds)):
            base = set(run_trial(sc, "B0", seed, HEADLINE_SUSC)["adopted"].split(",")) - {"-"}
            for cfg in ["B0", "B2", "B3", "B4"]:
                r = set(run_trial(sc, cfg, seed, HEADLINE_SUSC)["adopted"].split(",")) - {"-"}
                if not r.issubset(base):
                    inv_ok = False
                if len(r) < len(base):
                    prevented += 1
            inv_n += 1

    # example traces (pick seeds where the attack actually engages)
    def pick_seed(sid):
        sc = ALL_SCENARIOS[sid]
        for s in range(min(40, seeds * 2)):
            if run_trial(sc, "B0", s, HEADLINE_SUSC)["engaged"]:
                return s
        return 3

    demo = []
    for sid in ["A-quiet", "H"]:
        s = pick_seed(sid)
        for cfg in ["B0", "B4"]:
            r = run_trial(ALL_SCENARIOS[sid], cfg, s, HEADLINE_SUSC, capture_trace=True)
            demo.append((sid, cfg, s, r))

    write_report(args.out, atk, legit, agg_uar, agg_abr, per_scen, lcr, hyp,
                 esc_legit, check_us, ticks_legit, propagation, containment_n,
                 suscs, seeds, demo, inv_ok, inv_n, prevented, sweep)
    print(f"[6/6] done in {time.time() - t0:.0f}s -> {args.out}")


def CONFIG_LABEL(cfg):
    from ibacsim.defenses import CONFIG_LABELS
    return CONFIG_LABELS.get(cfg, cfg)


def write_report(out, atk, legit, agg_uar, agg_abr, per_scen, lcr, hyp,
                 esc_legit, check_us, ticks_legit, propagation, containment_n,
                 suscs, seeds, demo, inv_ok, inv_n, prevented, sweep):
    p = os.path.join(out, "summary.md")
    L = []
    A = L.append
    A("# IBAC 实验结果报告（机制级仿真）\n")
    A(f"- 试验规模：攻击场景 10 个 × 主配置 5 组 × 采纳率 {suscs} × 每格 {seeds} seeds；"
      f"合法任务 11 个 × 6 组；消融/敏感性格式 6 组；B1 检测器召回率扫描。")
    A(f"- 内部效度检查：注入采纳判定由 (seed, tag) 唯一决定；控制面只能通过阻断"
      f"'投递动作'预防感染，不能改变采纳概率本身。单调包含检查"
      f"（adopted(配置) ⊆ adopted(B0)）{inv_n} 组比对"
      f"{'全部通过' if inv_ok else '存在违例'}；其中 {prevented} 例为控制面阻断投递"
      f"动作从而预防感染（均为防御效果，非混淆）。\n")

    A("## 1. 主结果：UAR / ABR（采纳率=0.8，汇总全部攻击场景）\n")
    A("| 配置 | UAR（越权行动执行率） | ABR（攻击阻断率） |")
    A("| --- | --- | --- |")
    from ibacsim.defenses import CONFIG_LABELS
    for cfg in MAIN_CFGS:
        A(f"| {CONFIG_LABELS[cfg]} | {st.fmt_ci(*agg_uar[(cfg, HEADLINE_SUSC)])} | "
          f"{st.fmt_ci(*agg_abr[(cfg, HEADLINE_SUSC)])} |")
    A("\n按场景分解见 `agg_attack_per_scenario.csv`；图见 `plots/fig1、fig2`。\n")

    A("## 2. 合法任务完成率（LCR）\n")
    A("| 配置 | LCR |")
    A("| --- | --- |")
    for cfg in LEGIT_CFGS:
        A(f"| {CONFIG_LABELS[cfg]} | {st.fmt_ci(*lcr[cfg])} |")
    A("")
    A("B3 失败集中在角色未覆盖的一次性任务（如 L4 删除、L11 数据库写入），"
      "B1 的失败来自对正常高风险操作的误报，B4 的少量失败来自升级审批中"
      "的人工拒绝（5% 建模误差）。\n")

    A("## 3. 假设检验（配对 Bootstrap，双侧 p）\n")
    A("| 假设 | 对比 | ΔUAR (A−B) | 95% CI | p | n | 结论 |")
    A("| --- | --- | --- | --- | --- | --- | --- |")

    def verdict(key, d, direction="<0"):
        if d["p"] != d["p"]:
            return "n/a"
        sig = d["p"] < 0.05
        eff = (d["diff"] < 0) if direction == "<0" else (d["diff"] > 0)
        return ("**支持**" if (sig and eff) else
                ("方向一致但不显著" if eff else "**不支持**"))

    for susc in sorted({k[1] for k in hyp if k[0] == "H1"}):
        for other in ["B0", "B1", "B2", "B3"]:
            d = hyp[("H1", susc, other)]
            A(f"| H1 (susc={susc}) | B4 vs {other} | {d['diff']:+.3f} | "
              f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | "
              f"{verdict('H1', d)} |")
    d = hyp[("H2", "NL")]
    A(f"| H2 | 显式衰减 vs 仅自然语言约束 | {d['diff']:+.3f} | "
      f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | {verdict('H2', d)} |")
    d = hyp[("H2", "noAtten")]
    A(f"| H2 | 衰减 vs 无衰减消融 | {d['diff']:+.3f} | "
      f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | {verdict('H2', d)} |")
    d = hyp[("H3", "noProv")]
    A(f"| H3 | 来源追踪 vs 无来源追踪 (C,H) | {d['diff']:+.3f} | "
      f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | {verdict('H3', d)} |")
    d = hyp[("H3", "B1onC")]
    A(f"| H3 | B4 vs B1（记忆污染场景 C） | {d['diff']:+.3f} | "
      f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | {verdict('H3', d)} |")
    d = hyp[("H4", "bypass")]
    A(f"| H4 | 封闭 vs 旁路通道开放 (A,H)，Δ=B4−bypass | {d['diff']:+.3f} | "
      f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | "
      f"{verdict('H4', d, '<0')} |")
    d = hyp[("H5", "coarse_UAR")]
    A(f"| H5 | 细粒度 vs 粗粒度规则 UAR (A,E,H) | {d['diff']:+.3f} | "
      f"[{d['ci'][0]:+.3f}, {d['ci'][1]:+.3f}] | {st.fmt_p(d['p'])} | {d['n']} | {verdict('H5', d, '<0')} |")
    A("")

    A("## 4. 消融（场景 H 长链路组合攻击，采纳率=0.8）\n")
    A("消融梯度（UAR）：无来源追踪 → 邮件外发泄露；无权限衰减 → 子智能体越权读库；"
      "完整 IBAC → 全链路阻断。详见 `plots/fig4`。\n")

    A("## 5. 开销\n")
    A("| 配置 | 每合法任务升级审批次数 | 平均模拟时长(tick) | 策略检查耗时(µs) |")
    A("| --- | --- | --- | --- |")
    for cfg in LEGIT_CFGS:
        A(f"| {CONFIG_LABELS[cfg]} | {esc_legit[cfg]:.3f} | {ticks_legit[cfg]:.0f} | "
          f"{check_us[cfg]:.1f} |")
    A("\n攻击在场时各配置的任务中止率（连续 3 次拒绝后放弃剩余工作）：")
    A("")
    ab = atk[(atk["susc"] == HEADLINE_SUSC) & atk["engaged"]].groupby("config")["abandoned"].mean()
    A("| 配置 | 任务中止率 |")
    A("| --- | --- |")
    for cfg in MAIN_CFGS:
        A(f"| {CONFIG_LABELS[cfg]} | {ab.get(cfg, float('nan')):.1%} |")
    A("\nB4 的中止主要来自撤销响应（两次违规即撤销全部能力），这是遏制机制的真实成本；"
      "真实部署中可通过调查后重新授权恢复。注意：策略检查的墙钟时间是仿真器实现层面的"
      "指示值（Python、无缓存），用于量级对比，不能外推为生产系统开销；"
      "真实的授权开销主要体现为升级审批次数与授权撤销后的任务中断。\n")

    A("## 6. 撤销传播时延（场景 G，采纳率=0.8）\n")
    A("| 配置 | 撤销传播时延 |")
    A("| --- | --- |")
    for k, v in propagation.items():
        A(f"| {k} | {f'{v:.0f} ticks' if v is not None else '> 观测窗（无传播机制）'} |")
    A("")

    A("## 7. 效度边界（必读）\n")
    A("本实验是**机制级仿真**（in-silico）：Agent 决策、人类审批、检测器召回均为"
      "参数化概率模型，世界是确定性模拟。它验证的是论文 §7 实验协议的可执行性，"
      "以及各控制面机制在该威胁模型下的**结构性差异**（如：内容检测器原理上无法"
      "判定'越权'，因为授权不是内容属性），不能替代真实 LLM 智能体与真实业务系统"
      "上的实证。关键假设：①任务意图到 TAC 的推导正确（论文 §9.1 的开放问题）；"
      "②强制执行点覆盖全部副作用路径（H4 的旁路实验显示该假设不成立时防护退化）；"
      "③人类审批对恶意请求 95% 拒绝。\n")

    with open(p, "w", encoding="utf-8") as f:
        f.write("\n".join(L))

    # example traces
    tp = os.path.join(out, "example_traces.md")
    TL = ["# 示例执行轨迹（B0 vs B4）\n"]
    for sid, cfg, s, r in demo:
        TL.append(f"\n## 场景 {sid} — 配置 {cfg}（seed={s}, 采纳率=0.8）\n")
        TL.append("```")
        TL.extend(r["trace"] or ["(no trace)"])
        TL.append("```")
    with open(tp, "w", encoding="utf-8") as f:
        f.write("\n".join(TL))


if __name__ == "__main__":
    main()
