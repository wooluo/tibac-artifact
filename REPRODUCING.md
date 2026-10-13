# 复现清单（REPRODUCING.md）

论文（中文版与英文版 TIBAC-paper-EN.md）中每一个定量主张对应的生成命令与输出位置。环境：Python ≥3.10；
仿真/形式化/策略引擎**零第三方依赖**；聚合与绘图需 numpy/pandas/matplotlib；
真实 LLM 实验需可访问 open.bigmodel.cn 的 API Key（`~/.glm_key` 或环境变量
`GLM_API_KEY`，模型默认 glm-4-flash）。

## 证据类型声明（对应审稿要求）

| 类型 | 内容 | 确定性 |
| --- | --- | --- |
| 确定性仿真 | §7.6 主表/H1–H5/消融/敏感性（除审批扫描外） | 完全可复现（(seed, 选择点) 定址，两次全量重跑逐位一致） |
| 概率参数扫描 | 审批质量敏感性（q=0.95→0.50） | 同上确定性 |
| 形式化验证 | §5.5 五性质 + 消融反例 | 穷举 BFS，确定性 |
| 参考实现基准 | §7.6 开销 6.3µs/p99 8.7µs | 墙钟测量，机器相关（单次运行结果） |
| 真实 LLM 实验 | §7.7（glm-4-flash, temperature 0.7） | 服务端采样非确定；提供全部原始轨迹 |

## 主张 → 命令 → 输出

| 论文主张 | 生成/验证命令 | 输出位置 |
| --- | --- | --- |
| 55,800 次试验；主表 UAR/ABR/LCR 及 95%CI；H1–H5；消融梯度；撤销传播时延；检测器扫描 | `python3 ibac_eval/run_experiments.py`（约 50 秒） | `ibac_eval/results/summary.md`、`trials_attack.csv`、`trials_legit.csv`、`agg_*.csv`、`plots/fig1–7` |
| 上述每个数字与论文正文的逐项比对（46 项） | `python3 audit/check_paper_claims.py` | `audit/audit_report.md`（46/46 PASS） |
| 审批质量敏感性（UAR 0.5%→6.2%、LCR 99%→91%） | 审计脚本第"敏感性"节（重跑对应单元） | 同上 |
| 五项性质穷举验证 + 消融反例 + 状态数（1,944/6,318） | `python3 formal/verify.py` | `formal/verification_report.md`（含转移规则与反例轨迹） |
| 策略引擎 8 项自测（作用域/汇点/租约/预算/撤销/委派交集/防篡改） | `python3 prototype/tibac_engine.py` | stdout（ALL PASSED） |
| 裁决开销 6.3µs / p99 8.7µs / 0.013% | `python3 prototype/bench_overhead.py` | `prototype/bench_results.md` |
| 真实 LLM 对照（B0–B4 + 强基线，glm-4-flash） | VM 或任意可访问 API 的环境：`python3 ibac_eval/real/run_real.py --trials 5 --legit-trials 3 --workers 4`（另跑 `--only B4-coarse B4-noAtten --trials 3`），然后 `python3 ibac_eval/real/aggregate_real.py` | `real/real_trials.csv`、`real/real_trials_extra.csv`（逐次试验原始数据，已随稿存档——服务端采样不可精确重放，论文 §7.7 数值由这两份 CSV 确定性聚合而得）、`real/results_real.md` |
| 引用逐条核实记录（18+2 条） | 人工 + WebFetch/arXiv 比对（会话存档） | `audit/audit_report.md` 引用节 |
| 方程 ↔ 代码三方一致性审查 | `audit/equations_and_models.md`（静态文档） | 同左 |

## 指标分子/分母的精确定义

见论文 §7.4 与 `ibac_eval/README.md`：每次未授权尝试 ∈ {被阻断, 已执行, 未定}；
UAR=严重未授权执行数/尝试数，ABR=阻断数/尝试数，三者按尝试加和为 1；
LCR=完成断言通过的任务数/任务数（断言随场景提供）。

## 统计方法

Bootstrap 置信区间（2,000 次重采样、百分位法）；假设检验为配对 Bootstrap
（4,000 次重采样、双侧），配对单位 (场景, seed)；H1 家族 16 组比较经 Holm 校正。
实现：`ibac_eval/ibacsim/stats.py`。

## 版本

- 仿真/形式化/引擎：纯标准库（Python 3.11 验证于 macOS / 3.14 验证于 Kali ARM64）
- 真实实验：urllib（标准库）调用 OpenAI 兼容接口
- 本清单与论文稿件、全部工件的对应版本见仓库当前提交
