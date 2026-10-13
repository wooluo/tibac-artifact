# 相关工作对比与定位（供论文 Related Work 与引言使用）

> 全部引用已于 2026-10 在线核实存在；经典文献（TBAC/RBAC/非干扰/信任管理）凭记忆
> 列出，落笔引用前请再核对年份与出处。

## 1. 对比矩阵

| 系统/模型 | 定位 | 授权对象 | 任务生命周期绑定（租约/预算/到期/回收） | 委派衰减 C_c⊆C_p∩C_d | 撤销传播 | 来源/污点追踪 | 形式化属性 | 跨运行时可移植 | 对照实验 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| OpenClaw（工程产品） | 个人 Agent 网关 | 静态配置（tools.deny） | ✗ | ✗ | ✗ | ✗ | ✗ | 自身网关 | ✗ |
| AIOS (arXiv:2403.16971) | Agent OS 内核 | 用户组（静态角色式） | ✗ | ✗ | ✗ | ✗ | ✗ | 需采用 AIOS | ✗ |
| Agent libOS (arXiv:2606.03895) | Library-OS 运行时基底 | 进程身份+typed capabilities | ~（预算/Task Authority） | ~（进程谱系） | 未明确（摘要未述） | ✓（标签传播/汇点解析） | 架构级 | 需采用其运行时 | ✗ |
| Progent (arXiv:2504.11703) | 工具级特权策略引擎 | 策略 DSL | ✗ | ✗ | ✗ | ✗ | 部分 | 框架插件 | 部分 |
| CaMeL (arXiv:2503.18813) | 防提示注入的系统设计 | 值的能力标签（IFC） | ✗ | ✗（单智能体） | ✗ | ✓ 核心 | ✓（IFC 视角） | 需用其解释器 | ✓ AgentDojo |
| OWASP ACS | 运行时治理 wire 标准 | 策略文件+标签流 | 部分 | ✗ | 部分 | ✓ 标签流 | ✗ | ✓ 标准化协议 | ✗ |
| TBAC（Thomas & Sandhu 1997，经典） | 面向任务的访问控制 | 预定义工作流步骤 | ~（步骤授权） | ✗ | ✗ | ✗ | ✓ | — | — |
| **TIBAC（本文）** | **独立的访问控制模型** | **意图派生任务契约（TAC）** | **✓ 核心** | **✓ 形式化+验证** | **✓ 验证** | **✓ 属性二** | **✓ 五性质穷举验证** | **✓ 模型级，可实例化于上述任意运行时/标准** | **✓ B0–B4+消融+H1–H5** |

注："？"两处需拿到 Agent libOS 全文核对后填写。

## 2. 三句差异化定位

- **对 Agent libOS**：libOS 要求整体更换运行时基底；TIBAC 是可移植的授权语义——同一
  模型可实例化在 libOS、OpenClaw 网关或 OWASP ACS 拦截点上（libOS 是"换操作系统"，
  TIBAC 是"门禁规范"）。
- **对 CaMeL**：CaMeL 用能力与信息流控制解决提示注入这一个向量、面向单智能体；
  TIBAC 覆盖任务全生命周期授权（预算、到期、撤销传播、审计关联）与多智能体委派
  衰减，防注入只是属性二的推论之一。
- **对 Progent**：Progent 是工具级策略 DSL；TIBAC 的授权对象是意图派生契约，并给出
  委派衰减、撤销传播的形式化性质、穷举模型检验验证与机制级量化评估。

## 3. 引言定位段（可直接改写进论文）

模型内生对齐路线（如 Hermes 等）依赖 LLM 自身遵循规则，面对提示注入与幻觉只能提供
概率性安全。系统层工作已证明确定性约束的必要：工业界（OpenClaw 网关、沙箱）与学术
界（AIOS 的用户组访问管理、Agent libOS 的能力受控运行时）在执行环境层面实施拦截；
OWASP ACS 正在标准化跨框架的策略执行钩子。研究侧，CaMeL 以能力与信息流控制防御
提示注入，Progent 提供工具级特权策略 DSL。**但现有工作缺少一套独立、可形式化、跨
运行时的访问控制模型：授权不随任务生命周期管理——没有意图派生的授权契约，没有预算
与到期，没有子任务委派时的权限衰减原语，也没有撤销传播与审计关联的安全属性。**
本文提出 TIBAC（Task-Intent Bound Access Control）：将权限绑定任务契约而非身份，
随任务生命周期自动衰减与回收；模型独立于运行时，可叠加于上述任意系统之上；并以
穷举模型检验（五性质+消融反例）、B0–B4 机制级仿真（H1–H5）与微秒级参考实现
共同验证。

## 4. 命名决策（重要）

- IBAC 已被 Identity-Based Access Control 占用（NIST 术语体系）——保留缩写必然引起混淆；
- TBAC 已被 Task-Based Access Control（Thomas & Sandhu 1997）占用，且恰是本文必须
  对比引用的经典——**不可用**；
- **推荐 TIBAC（Task-Intent Bound Access Control）**：无已知冲突，语义准确，与论文
  已有 TAC（Task Authorization Contract）命名体系自洽。

## 5. 审稿人建议的红队评估 ↔ 已完成实验的映射

| 评审建议的攻击场景 | 已实现 | 结果（采纳率 0.8） |
| --- | --- | --- |
| 提示注入"删除所有数据库表" | 场景 A-quiet/A-loud + H | B1 检测器 UAR 73.5% → B4 0.5%；召回扫到 0.95 仍剩 ~70% |
| 权限漂移（任务后期调用未授权 API） | 场景 F（目标漂移链） | B0 100% 执行 → B4 0%（低风险读走升级审批，高危直接拒） |
| 子任务越权（子任务尝试写操作） | 场景 E + H（委派衰减） | 无衰减消融 UAR 52% → 显式衰减 0%；NL-only 遵守 87% 泄露 |
| 对比基线：纯 System Prompt 约束 / 基础沙箱 | B1（模型侧提示+检测）/ B2（沙箱） | B1 UAR 73.5%、B2 80.6% vs B4 0.5%，全部 p<0.001 |

## 6. 建议引用清单（分组）

**Agent 安全近期工作（已核实）**
- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv:2503.18813, 2025
- Shi, He, ..., Song, *Progent: Programmable Privilege Control for LLM Agents*, arXiv:2504.11703, 2025
- Zhang, Y., *Agent libOS: A Runtime Substrate for Capability-Controlled Self-Evolving LLM Agents*, arXiv:2606.03895, 2026（SOSP'26 AgenticOS workshop，独作）
- Mei et al., *AIOS: LLM Agent Operating System*, arXiv:2403.16971, 2024
- Zhang et al., *MCP Security Bench*, arXiv:2510.15994（论文已引 [3]）
- Alpay, *AgentSecBench*, arXiv:2605.26269（论文已引 [4]）
- OWASP GenAI：Agentic Top 10 2026（已引 [1]）；Agent Control Standard（已引 [5]，
  注意补充事实：源自微软 Agent Control Specification，2026-09 捐赠 OWASP，Guardian
  Agent 拦截模式，含无状态标签流 IFC）

**经典访问控制/委派/信息流（文献综述补强，引用前核对）**
- Saltzer & Schroeder, 最小权限， 1975
- Sandhu et al., RBAC96, 1996
- Thomas & Sandhu, Task-Based Access Control (TBAC), 1997 —— 必引并对比
- Hu et al., NIST SP 800-162 (ABAC), 2014
- Blaze et al., Trust Management, 1996；SPKI/SDSI 委托证书
- Goguen & Meseguer, Noninterference, 1982；Rushby, Intransitive Noninterference, 1992
- Dennis & Van Horn, Capability 安全, 1966
- Zeldovich et al., Distributed Information Flow Control, 2006
