# TIBAC 形式化验证报告（显式状态模型检验）

> 运行 `python3 formal/verify.py` 可完全复现本报告（无外部依赖）。

## 1. 系统模型（有限域上的标记转移系统）

状态 `s = (t, st, ℓ, b, C_p, C_c, C_g, child, grand, rv_p, rv_c, rv_g, pend, u)`：时钟、任务状态（RUN/DONE/TERMINATED）、租约剩余、预算、父/子/孙有效能力集（**两级委派链**）、各级撤销位、待提交动作（仅 check-then-act 引擎）与非可信内容 `u`（真实状态分量，V2 孪生比较因此非空洞）。初始状态：任务 RUN、租约 3、预算 3、父能力为完整契约、无子/孙、无非可信内容。
动作域 `{read,write,send} × {proj_doc, finance_doc, cred_store, db_reports, ext_mail, int_mail}`；契约 `C_p = {r/w proj_doc, r db_reports, send int_mail}`；子与孙的委派许可 `C_d = C_d2 = {r proj_doc}`；`BUDGET=3, LEASE=3`。
转移规则：`tick`（时钟+1、租约-1、到期清全部能力）；`untrusted=u′`；`task_done / task_terminated`（清全部能力）；`revoke(parent/child/grandchild)`（**级联清空所有后代能力**）；`spawn_child / spawn_grandchild`（衰减：∩C_d / ∩C_d2，无衰减引擎则继承全部）；`*_finish`；`exec(actor,op,res)`（原子判定+执行）；check-then-act 引擎为 `check` + `commit_naive`（不复查——TOCTOU 竞态源，检查与提交之间可插入到期/终止/撤销）；旁路引擎含 `bypass_exec`。判定 `Permit(s,a,actor) ⇔ st=RUN ∧ ℓ>0 ∧ b>0 ∧ ¬rv(actor) ∧ a∈C_actor`，不读取 `u`（由 V2 孪生比较验证）。

## 2. 验证的性质

| 编号 | 性质 | 公式（对全部可达状态/转移） |
| --- | --- | --- |
| V1 | 行动授权约束（轨迹版，§5.1） | ∀轨迹∀事件：Commit(e) ⇒ AuthorizedAtCommit(前态,e)，Grant 以意图契约为基准（父=C_p，子/孙=C_d） |
| V2 | 受限授权非干扰（§5.2） | ∀s∈Reach：Permit(s[u:=u′],·)=Permit(s,·)（孪生/展开式；u 为状态分量，判定误读 u 即失败） |
| V3 | 委派不扩张（两级，§5.3） | AG( child→C_c⊆C_p∩C_d ∧ grand→C_g⊆C_c∩C_d2 )（即 V3a 语义版 + V3b 递归约束） |
| V4 | 模型内审计完备（§5.4） | 审计与执行原子写入，故归约为旁路不可达；日志篡改与节点失陷在模型外（§5.4 文字限定） |
| V5 | 租约/生命周期公理 | AG( (ℓ=0 ∨ st≠RUN ∨ 自身或任一祖先撤销) → 该级有效能力=∅ )（V3c 级联的公理化） |

## 3. 结果

| 引擎变体 | 状态数 | 转移数 | V1 | V2 | V3 | V4 | V5 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E1 TIBAC-full | 4572 | 29601 | ✓ | ✓ | ✓ | ✓ | ✓ |
| E2 naive check-then-act | 18144 | 129312 | ✗ | ✓ | ✓ | ✓ | ✗ |
| E3 no-attenuation | 4572 | 29844 | ✗ | ✓ | ✗ | ✓ | ✓ |
| E4 bypass channel | 4572 | 31149 | ✗ | ✓ | ✓ | ✗ | ✓ |

**结论：** V1–V5 在完整 TIBAC（E1）上全部成立；每个消融引擎对应**独立的失效模式**（E2 败于 V1/V5 的 TOCTOU 竞态、E3 败于 V3/V1 的委派扩张（含孙级）、E4 败于 V1/V4 的旁路），即各机制是相应性质的必要条件而非重复计数。

## 4. 机器生成的反例（验证器实际输出）

### E2 naive check-then-act — V1

```
  0. init                       st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  1. check(p,read,proj_doc)     st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  2. task_done                  st=DONE lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  3. <<exec>>                   st=DONE lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
```

### E2 naive check-then-act — V5

```
  0. init                       st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  1. task_done                  st=DONE lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
```

### E3 no-attenuation — V1

```
  0. init                       st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  1. spawn_child                st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_g=[] rv=(0,0,0)
  2. <<exec>>                   st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_g=[] rv=(0,0,0)
```

### E3 no-attenuation — V3

```
  0. init                       st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  1. spawn_child                st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_g=[] rv=(0,0,0)
```

### E4 bypass channel — V1

```
  0. init                       st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  1. <<exec>>                   st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
```

### E4 bypass channel — V4

```
  0. init                       st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
  1. <<bypass_exec>>            st=RUN lease=3 budget=3 cap_p=['read/db_reports', 'read/proj_doc', 'send/int_mail', 'write/proj_doc'] cap_c=[] cap_g=[] rv=(0,0,0)
```

## 5. 假设与范围

- 验证器：约 400 行纯 Python、显式 BFS、无对称约简、有限状态空间（含非可信内容分量与两级委派）；性质即代码中的谓词（机器可读）。
- 结论限定于该有限模型与假设：能力集单调不增（不含用户再授权），网络分区与时钟偏移被排除（论文 §9.4）；穷举结论不能外推为生产环境的普遍安全证明。四层证据（安全目标/形式化定义/模型验证/实现保证）中，本报告只覆盖第三层，实现层由参考引擎与真实 LLM 实验提供。
- E2/E3/E4 为消融引擎，对应仿真 H4 与论文 §9.3 的敏感性分析。