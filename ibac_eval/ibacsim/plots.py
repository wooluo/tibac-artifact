"""Figures (English labels for portability; Chinese used in summary.md)."""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

COLORS = {"B0": "#9e9e9e", "B1": "#f39c12", "B2": "#27ae60", "B3": "#e74c3c",
          "B4": "#2962ff", "B4-noProv": "#7e57c2", "B4-noAtten": "#26a69a",
          "B4-noRev": "#ef6c00", "B4-NL": "#c2185b", "B4-coarse": "#5d8aa8",
          "B4-bypass": "#b71c1c"}
LABELS = {"B0": "B0 baseline", "B1": "B1 detector", "B2": "B2 sandbox",
          "B3": "B3 RBAC", "B4": "B4 IBAC", "B4-noProv": "IBAC w/o provenance",
          "B4-noAtten": "IBAC w/o attenuation", "B4-noRev": "IBAC w/o revocation",
          "B4-NL": "IBAC NL-only delegation", "B4-coarse": "IBAC coarse",
          "B4-bypass": "IBAC w/ unmediated channel"}
MAIN = ["B0", "B1", "B2", "B3", "B4"]


def _save(fig, path):
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


def fig_uar_vs_susc(agg, suscs, path):
    """agg: dict (config, susc) -> (mean, lo, hi) of UAR aggregated over attacks."""
    fig, ax = plt.subplots(figsize=(6.4, 4.2))
    for cfg in MAIN:
        xs, ys, los, his = [], [], [], []
        for s in suscs:
            m, lo, hi = agg.get((cfg, s), (np.nan,) * 3)
            xs.append(s); ys.append(m); los.append(lo); his.append(hi)
        ys, los, his = np.array(ys), np.array(los), np.array(his)
        ax.plot(xs, ys, "o-", color=COLORS[cfg], label=LABELS[cfg], lw=2, ms=5)
        ax.fill_between(xs, los, his, color=COLORS[cfg], alpha=0.15)
    ax.set_xlabel("Injection adoption probability (model susceptibility)")
    ax.set_ylabel("UAR: unauthorized actions executed (%)")
    ax.set_ylim(-3, 103)
    ax.grid(alpha=0.3)
    ax.legend(fontsize=8, loc="upper left")
    _save(fig, path)


def fig_abr_uar(agg, path, susc=0.8):
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.8), sharey=True)
    for ax, key, title in zip(axes, ["uar", "abr"],
                              ["UAR (executed, %)", "ABR (blocked, %)"]):
        vals = [agg.get((c, susc, key), (np.nan,) * 3) for c in MAIN]
        means = [v[0] * 100 for v in vals]
        errs = [[max(0, (v[0] - v[1]) * 100) for v in vals],
                [max(0, (v[2] - v[0]) * 100) for v in vals]]
        ax.bar(range(len(MAIN)), means, color=[COLORS[c] for c in MAIN],
               yerr=errs, capsize=3)
        ax.set_xticks(range(len(MAIN)))
        ax.set_xticklabels(MAIN)
        ax.set_title(title, fontsize=10)
        ax.grid(alpha=0.3, axis="y")
        ax.set_ylim(0, 105)
    _save(fig, path)


def fig_lcr(lcr, path):
    """lcr: dict config -> (mean, lo, hi)."""
    cfgs = MAIN + ["B4-coarse"]
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    means = [lcr.get(c, (np.nan,) * 3)[0] * 100 for c in cfgs]
    errs = [[max(0, lcr.get(c, (0, 0, 0))[0] - lcr.get(c, (0, 0, 0))[1]) * 100 for c in cfgs],
            [max(0, lcr.get(c, (0, 0, 0))[2] - lcr.get(c, (0, 0, 0))[0]) * 100 for c in cfgs]]
    ax.bar(range(len(cfgs)), means, color=[COLORS[c] for c in cfgs], yerr=errs, capsize=3)
    ax.set_xticks(range(len(cfgs)))
    ax.set_xticklabels(cfgs, rotation=20)
    ax.set_ylabel("LCR: legitimate task completion (%)")
    ax.set_ylim(0, 105)
    ax.grid(alpha=0.3, axis="y")
    _save(fig, path)


def fig_ablation(cells, path):
    """cells: list of (label, mean_uar, lo, hi) for scenario H (and C/E/G)."""
    fig, ax = plt.subplots(figsize=(7.4, 4.0))
    xs = np.arange(len(cells))
    means = [c[1] * 100 for c in cells]
    errs = [[max(0, (c[1] - c[2]) * 100) for c in cells],
            [max(0, (c[3] - c[1]) * 100) for c in cells]]
    colors = [COLORS.get(c[0].split()[0], "#888") if c[0].startswith("B4")
              else COLORS.get(c[0], "#888") for c in cells]
    ax.bar(xs, means, color=colors, yerr=errs, capsize=3)
    ax.set_xticks(xs)
    ax.set_xticklabels([c[0] for c in cells], rotation=25, ha="right", fontsize=8)
    ax.set_ylabel("UAR on scenario H / C / E (%)")
    ax.grid(alpha=0.3, axis="y")
    _save(fig, path)


def fig_overhead(esc_legit, check_us, path):
    fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.8))
    cfgs = MAIN + ["B4-coarse"]
    vals = [esc_legit.get(c, 0) for c in cfgs]
    axes[0].bar(range(len(cfgs)), vals, color=[COLORS[c] for c in cfgs])
    axes[0].set_xticks(range(len(cfgs))); axes[0].set_xticklabels(cfgs, rotation=20)
    axes[0].set_title("Human escalations per legitimate task", fontsize=10)
    axes[0].grid(alpha=0.3, axis="y")
    vals = [check_us.get(c, np.nan) for c in cfgs]
    axes[1].bar(range(len(cfgs)), vals, color=[COLORS[c] for c in cfgs])
    axes[1].set_xticks(range(len(cfgs))); axes[1].set_xticklabels(cfgs, rotation=20)
    axes[1].set_title("Policy check wall time (µs, simulator-level)", fontsize=10)
    axes[1].grid(alpha=0.3, axis="y")
    _save(fig, path)


def fig_detector_sweep(sweep, b4_line, path):
    """sweep: list of (recall, uar_mean); b4_line: float."""
    fig, ax = plt.subplots(figsize=(6.0, 3.8))
    xs = [s[0] for s in sweep]; ys = [s[1] * 100 for s in sweep]
    ax.plot(xs, ys, "o-", color=COLORS["B1"], lw=2, label="B1 detector (recall sweep)")
    ax.axhline(b4_line * 100, color=COLORS["B4"], ls="--",
               label="B4 IBAC (no content detector)")
    ax.set_xlabel("Detector recall on loud attacks")
    ax.set_ylabel("UAR aggregated over attacks (%)")
    ax.grid(alpha=0.3); ax.legend(fontsize=9)
    _save(fig, path)


def fig_latency(containment, propagation, path):
    fig, ax = plt.subplots(figsize=(7.0, 3.8))
    labels = list(propagation.keys())
    xs = np.arange(len(labels))
    props = [propagation[l] for l in labels]           # mean ticks or None
    disp = [p if p is not None else 0 for p in props]
    bars = ax.bar(xs, disp, color=["#2962ff" if p is not None else "#cccccc"
                                   for p in props])
    for x, p in zip(xs, props):
        ax.text(x, (p if p is not None else 0) + 0.5,
                f"{p:.0f}t" if p is not None else "> horizon",
                ha="center", fontsize=8)
    ax.set_xticks(xs)
    ax.set_xticklabels(labels, rotation=20, fontsize=8)
    ax.set_ylabel("Revocation propagation latency (ticks)")
    ax.set_title("Time from revocation to rejection at executing nodes "
                 f"(containment events: {containment})", fontsize=9)
    _save(fig, path)
