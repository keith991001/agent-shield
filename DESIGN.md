# agent-shield — Design Document

| | |
|---|---|
| Status | MVP complete |
| Author | keith991001 |
| Last revised | 2026-05-27 |
| Repository | <https://github.com/keith991001/agent-shield> |

> 实时观测 AI Agent 运行时的所有 syscall,在内核侧毫秒级阻断危险动作,并由 LLM 提供事后风险解释。

本文档为 agent-shield 的完整设计依据。面向后续维护者、贡献者及希望复现实现的读者,涵盖系统动机、整体架构、关键设计取舍、组件细节及演进路径。实施细节及"设计经验"散文版本请参见 [BLOG.md](BLOG.md)。

---

## 1. 概述

LLM 驱动的编码 Agent(Claude Code、Cursor Agent、Devin 等)会执行任意 shell 命令、读写文件、发起网络请求。一次错判或一次 prompt injection 即可导致:

- 不可逆的文件破坏 (`rm -rf /usr/bin`)
- 凭据外泄 (`/etc/shadow`、`~/.ssh/`、`.env`)
- 内部网络资源攻击

`agent-shield` 是一个独立 Linux daemon,与 Agent 进程并行运行。其职责是:

1. **观测**:在内核层捕获 5 类核心 syscall (`execve` / `openat` / `unlinkat` / `connect` / `socket`)
2. **判定**:通过 YAML 配置的规则引擎,按 first-match-wins 语义判断 `log` / `alert` / `block`
3. **干预**:对 `block` 规则触发即时 `SIGKILL`
4. **解释**:对 alert / block 事件,异步调用 Anthropic Messages API 由 Claude 给出 0-100 风险评分及简要原因

整个系统打包为单一二进制(约 12 MB),内嵌 WebSocket dashboard,可独立部署。

---

## 2. 设计动机

### 2.1 现有方案的不足

现行 AI Agent 沙箱方案大致可归为三类:

| 类别 | 代表 | 隔离强度 | 内部可观测性 | 实时干预能力 |
|---|---|---|---|---|
| 主机直接执行 + 权限白名单 | Claude Code, Cursor Agent | 弱 | 仅用户审批 | 仅前置 |
| microVM 隔离 | Devin, E2B | 强 | 不可见 | 不具备 |
| 容器/gVisor | Daytona, devcontainer | 中 | 受限 | 不具备 |

权限白名单依赖用户判断,无法覆盖未预见的危险组合;microVM 提供良好边界但内部是黑盒,无法说明 Agent 在 VM 内究竟做了什么。

### 2.2 系统定位

`agent-shield` 不试图替代上述任一方案,而是补足"**事中(during)**"这一层:

```
事前(permission)  ────  事中(agent-shield)  ────  事后(audit)
  能做什么            正在做什么 / 拦不拦         做过什么
```

可与 microVM 叠加使用:microVM 提供边界,`agent-shield` 提供边界内部的实时观测与策略执行。

---

## 3. 目标与非目标

### 3.1 设计目标

- **G1**. 内核层 syscall 观测,延迟低于 1 ms。
- **G2**. 声明式规则配置,运维人员可在不修改代码的情况下调整策略。
- **G3**. 实时阻断:命中 `block` 规则的进程在 SIGKILL 路径上无 LLM 等延迟依赖。
- **G4**. 单二进制部署,无外部服务依赖,无 Node 工具链。
- **G5**. 单机即可演示;支持后续平滑演进到多机/SaaS 形态。
- **G6**. LLM 风险解释采用 **multi-turn tool-use 调查员模式**而非单次 API 调用,使评分质量随 prompt/工具改进而单调上升,且每次决策具备可解释的"证据链"。
- **G7**. 配套 **offline eval 框架** —— 对调查员 Agent 的分类准确率提供可重复、可比较的离线评测;每次 prompt 修改可量化效果。

### 3.2 非目标(本期不做)

- **NG1**. 完整沙箱(不替代 Firecracker / gVisor / Kata)。
- **NG2**. Kubernetes 原生集成(列入演进路径,见 §9)。
- **NG3**. LLM 参与阻断决策。LLM 仅做事后解释,不在 critical path。
- **NG4**. 跨平台支持。eBPF 仅 Linux,本系统不计划支持 Windows / macOS host。
- **NG5**. 认证与多租户。MVP 假设单机、单用户、可信调用者。

---

## 4. 系统架构

### 4.1 组件总览

```
┌────────────────────────────────────────────────────────────────────┐
│                        Host (Linux ≥ 5.8)                          │
│                                                                    │
│  ┌────────────────┐        ┌────────────────────────────────┐      │
│  │  AI Agent      │ syscall│   Kernel                       │      │
│  │  (任意进程)    │ ─────► │  ┌──────────────────────────┐  │      │
│  │  uid = agent   │        │  │ eBPF programs            │  │      │
│  └────────────────┘        │  │   tracepoint hooks       │  │      │
│         ▲                  │  └────────────┬─────────────┘  │      │
│         │ SIGKILL          │               │ ring buffer    │      │
│         │                  └───────────────┼────────────────┘      │
│  ┌──────────────────────────────────────────▼──────────────┐       │
│  │  Userspace daemon (Go)                                  │       │
│  │  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐   │       │
│  │  │ Event reader│─►│ Rule engine  │─►│ Actioner     │   │       │
│  │  └─────────────┘  └──────────────┘  └──────────────┘   │       │
│  │                            │                            │       │
│  │                            ▼ async                      │       │
│  │                  ┌─────────────────────┐                │       │
│  │                  │ LLM scorer pool     │ Anthropic API │       │
│  │                  └─────────────────────┘                │       │
│  │                                                         │       │
│  │  Embedded HTTP server (port 8090):                      │       │
│  │  GET /            → static dashboard                    │       │
│  │  WS  /events      → broadcast every event               │       │
│  └─────────────────────────────────────────────────────────┘       │
│                                                                    │
│                     Browser (any modern browser)                   │
└────────────────────────────────────────────────────────────────────┘
```

### 4.2 事件数据流

以一次 `rm -rf /usr/bin` 为例,完整链路:

```
1. AI Agent 调用 unlinkat("/usr/bin/python3", ...)
2. 内核 sys_enter_unlinkat tracepoint 触发,eBPF 程序写事件至 ring buffer
   {pid=1234, comm="rm", uid=0, path="/usr/bin/python3", event_type=UNLINKAT}
3. 用户态 reader 从 ring buffer 解出,分配单调递增 ID
4. Rule engine 按 first-match-wins 匹配:命中 "protected_unlink"
   规则配置 action=block, severity=critical
5. Actioner 执行 kill(1234, SIGKILL)
6. 事件序列化为 JSON,广播至所有 WebSocket 客户端
7. 由于 severity ≥ medium,该事件被提交至 LLM scorer 队列
8. Worker 调用 Anthropic API,1-2 秒后获得评分:
   {risk: 92, category: "destructive", reason: "..."}
9. 同 ID 的事件被二次广播,Risk 字段填充
10. 前端按 ID 查找已渲染节点,原地更新 risk 行

延迟目标:
  步骤 1-5(拦截链路): < 5 ms
  步骤 1-9(含 LLM):  < 2 s
```

### 4.3 两阶段广播机制

高严重度事件经历两次独立的广播:

| 阶段 | 触发时机 | 内容 |
|---|---|---|
| 即时事件 | rule engine 完成后立即 | 完整事件结构,Risk 字段为空 |
| 异步评分 | LLM Worker 拿到 API 响应后 | 同 ID 事件,Risk 字段填充 |

前端通过 `Map<id, DOMNode>` 维护事件状态。第二次广播抵达时,定位到原 DOM 节点并原地更新,辅以 CSS 动画提示用户内容已变化。

该机制将"拦截决策"(deterministic, < 5 ms)与"风险解释"(probabilistic, ~1.5 s)解耦,保证了关键路径不被 LLM 延迟拖慢。

---

## 5. 关键设计决策

### 5.1 选用 Tracepoint 而非 Kprobe

| | Tracepoint | Kprobe |
|---|---|---|
| 跨内核版本稳定性 | 高(ABI 由内核显式导出) | 低(内部函数随版本重命名) |
| 参数布局文档 | `/sys/kernel/tracing/events/.../format` | 需读源码 |
| 性能 | 略快 | 略慢(动态插桩) |

本系统所有 5 个 hook 点均使用 `tracepoint:syscalls:sys_enter_*` 家族。

### 5.2 扁平事件结构与 Union 的取舍

事件结构包含全部可能字段(路径、socket 地址、协议等),按 `event_type` 区分有效字段。优点:

- BPF verifier 无 union 访问模式带来的约束
- Go 端无需根据类型反序列化不同结构
- 单一 ring buffer 即可承载所有事件

代价:每条事件冗余约 256 字节。对于 16 MiB ring buffer,该代价可忽略。

### 5.3 LLM 调用的异步化

LLM 调用具有以下特征:

- 延迟 1-2 秒(对实时拦截不可接受)
- 偶发性失败(API 限速、网络问题)
- 单价非零(每次约 $0.0008)

因此采用:

- **异步**:LLM 调用不在 critical path,失败/超时不影响拦截
- **有界并发**:4 个 worker、256 容量队列,队列满则丢弃
- **筛选触发**:仅 severity ≥ medium 且命中规则的事件提交评分

由此带来的可观测延迟约 1.5 秒(从事件渲染到 risk 评分淡入),用户体验上仍可感知"实时"。

### 5.4 First-match-wins 的规则匹配语义

规则列表按文件顺序遍历,命中即返回。该语义来自 iptables,优点是:

- 行为可预测,易于阅读
- 简单的"特例先于通用"模式可直接表达
- O(n) 查询足以应对典型规则集规模(< 50 条)

不采用最长前缀匹配或决策树等更复杂方案,理由是 MVP 阶段规则集小且规则编写者愿意按显式顺序组织。

### 5.5 SIGKILL 阻断及其延迟特性

用户态收到事件后调用 `kill(pid, SIGKILL)`,但事件本身的 syscall 已经执行。即:

- `rm -rf /usr/bin` 触发的**第一个** unlinkat 已完成,首文件已删除
- 第二个 unlinkat 之前进程被 SIGKILL,后续 99 个文件得以保留

该模式称为"近似阻断"。实际效果上,绝大多数破坏性操作需要多个 syscall 完成,保留 N-1 即可显著降低破坏面。

真正同步阻断需要 eBPF LSM hooks(内核 ≥ 5.7,需 LSM-BPF 编译选项),列入演进路径(见 §9)。

### 5.6 LLM 集成采用 Tool-Use Agent Loop 而非单次调用

最初版本将 LLM 用作"一次性评分器":一次 API 调用,模型基于事件字段输出 risk + reason。此方案的缺点:

- **信息不足**:模型只能看到事件本身,无法获取进程上下文(父进程、最近行为)、目标文件元数据
- **质量天花板低**:任何"它需要看一下 `/proc/PID` 才能判断"的场景都无解
- **可解释性弱**:reason 字段只是"听起来合理",无法引证具体证据

升级方案:Claude `tool_use` API 多轮循环。模型可主动调用三个工具:

| 工具 | 输入 | 返回 |
|---|---|---|
| `get_process_info` | pid | `/proc/PID/{status,cmdline}` 解析后的字段 |
| `recent_events_for_pid` | pid, n | 该 PID 最近 N 条 syscall 事件 |
| `path_metadata` | path | 文件类型/大小/权限/是否系统关键路径 |

每个事件触发的对话最多 6 轮,最终输出与之前同形态的 `{risk, category, reason}` JSON。

代价:每次评分由 1 次 API 调用变为 1-3 次。Haiku 4.5 价格下仍低于 $0.01/event。
收益:reason 字段开始出现"父进程是 bash,该 PID 最近做了 5 次 .env 读取,呈典型外泄模式"之类引证证据的文本。

### 5.7 配套 Offline Eval 框架

不能量化的系统改不动。本系统提供 `evals/scenarios.yaml` 作为离线评测基线:

- 14 个手动标注的场景,覆盖 destructive/exfiltration/recon/egress/benign 五类
- 每场景定义期望的 `risk_min..risk_max` 区间及 `category`
- `agent-shield -eval evals/scenarios.yaml` 跑全套并输出聚合指标

为何选 risk 区间而非精确值:LLM 输出是概率分布,设阈值带容差更符合实际。
为何选离线模式:不依赖 eBPF,可在任意 Linux/macOS 主机(含 CI)运行;调试 prompt 时反馈循环短。

### 5.8 Plan-Execute-Synthesize 工作流(取代纯 ReAct)

初版 investigator agent 是经典 ReAct 模式:思考一步、调一个工具、看结果、再思考。该模式简单但有两个缺点:

1. **轮次浪费**:三个独立工具(`get_process_info` / `recent_events_for_pid` / `path_metadata`)被串行调用,每次 API 调用都需往返一次网络
2. **缺少 meta 推理**:模型没有显式"先想清楚要查什么再去查"的机会,容易遗漏关键查询

升级方案是 system prompt 强制三阶段流程:

| 阶段 | 模型动作 | 期望产物 |
|---|---|---|
| **SCAN** | 内部判定事件是否明显良性 | 若良性 → 直接 verdict 跳过 PLAN/EXECUTE |
| **PLAN** | 在 text 块中写一两句计划,列出要用哪些工具及理由 | "I'll check parent, recent history, and target metadata" |
| **EXECUTE** | **同一个 assistant message** 内并行 emit 多个 `tool_use` 块 | 一次 round-trip 拿回所有所需信息 |
| **SYNTHESIZE** | 读 tool results,1 句话总结,然后 emit verdict JSON | `{risk, category, reason}` |

Anthropic Messages API 原生支持单条 assistant 消息含多个 `tool_use` 块,所有结果在一条 user 消息中以 `tool_result` 列表返回。我们的 `runTools()` 已实现该枚举,无需代码改动,**纯 prompt 工程升级**。

收益(预期,需 eval 验证):
- 单 scenario 平均 turns 由 ~4 降至 ~2-3
- 单 scenario 平均延迟由 ~3.5 s 降至 ~2 s
- token 消耗下降(少一轮 round-trip 的 system prompt 复发)
- 模型推理质量上升(显式 plan 步骤是 CoT 的具体实例)

代价:
- prompt 显著变长(影响 token 成本,可被 Anthropic prompt caching 抵消)
- 良性事件路径变长一行(SCAN 阶段需要显式说明跳过)

代码层面,`runAgentLoop` 返回从单纯的 `*scoreResult` 升级为 `*AgentTrace`,后者含 `Turns / TotalToolCalls / MaxParallelTools` 三项指标。eval 框架直接从 trace 读取这些数,聚合后纳入 summary。

### 5.9 Reflection (Self-Critique) 第二轮

Plan-Execute-Synthesize 出 verdict 后,代理多走一轮: 重读自己的结论,自问三个问题(良性解释/risk 校准/category 选对),要么坚持要么修订。AgentTrace 加 `Reflected/VerdictRevised` 两位 telemetry,使"reflection 是否值这一次额外 API 调用"成为可度量问题(eval 汇总会显示"14/14 reflected, 2 revised")。

代价:每 scored event 多 1 次 API 调用,~50% 额外 token。预期收益:边缘案例(risk=50 之类摇摆 verdict)校准更准,假阳/假阴率均有改善。

### 5.10 SQLite 持久化 Alert Archive

`EventHistory` 是进程级 in-memory ring buffer,daemon 重启即丢。新增 `AlertArchive`(`archive.go`)向 SQLite 持久化所有 matched events,并提供按 PID 的聚合查询。第 4 个 tool `get_pid_history(pid)` 让 investigator 能跨 session 查询"这个 PID 历史上 alert 几次、最高 risk 几分、最近两次原因",从而:

- 区分"一次性可疑事件" vs "持续模式"
- 长寿 agent 的行为漂移可追溯
- 跨 daemon 重启的取证

技术细节:
- 纯 Go 驱动 `modernc.org/sqlite`(避免引入 cgo,保持 cross-compile 容易)
- WAL + `synchronous=NORMAL`,适合写多读少
- 默认关闭(`-archive ""`),用 `-archive /var/lib/agent-shield.db` 启用

### 5.11 Prompt Caching 与 Token/Cost Telemetry

系统 prompt 现以 content-block array 形式发送,带 `cache_control={type:ephemeral}` 标记。当 prompt token 数超过模型缓存阈值(Sonnet 1024 / Haiku 2048),Anthropic 会自动复用——cache write 1.25×、cache read 0.1× 原 input 价。

API response 的 `usage` 字段被解析并累加到 `AgentTrace.{InputTokens,OutputTokens,CacheCreationTokens,CacheReadTokens}`。`EstimateCostUSD()` 按 Haiku 4.5 公开定价计算单次总成本。eval summary 显示总 input/output tokens、cache hit 数、估算 USD 成本。

虽然当前 system prompt 还未达 cache 阈值(实际不会真的缓存),但基础设施已就绪——未来 prompt 扩展(few-shot examples、知识库注入)立即得益。

### 5.12 A/B Prompt Eval

`evals/prompts.yaml` 定义 N 个 prompt variant,每个含 `{id, description, system_prompt}`。`-eval -eval-prompts <file>` 模式针对同一 scenarios 跑所有 variant,输出对比表(pass rate / avg turns / cost / failures)并标注 best-by-X 赢家。

每 variant 用独立 `LLMScorer` 实例(`WithSystemPrompt(p)`)防止状态串扰。退出码 0 iff 至少一个 variant 全过。

为何重要:prompt engineering 的"我感觉新版更好"是工业级 agent 系统回归的首要来源。A/B harness 把 prompt 改动从"凭感觉" 转成"数据驱动",这是 senior agent 工程师的工作流。

---

## 6. 组件细节

### 6.1 eBPF Probe 层

所挂载的 tracepoint:

| Probe | 抓取 | 用途 |
|---|---|---|
| `sys_enter_execve` | 进程启动 | 命令执行控制 |
| `sys_enter_openat` | 文件访问 | 敏感文件保护 |
| `sys_enter_unlinkat` | 文件删除 | 防止破坏性删除 |
| `sys_enter_connect` | 网络连接 | 出站流量控制 |
| `sys_enter_socket` | socket 创建 | 协议族审计 |

事件结构(写入 ring buffer 的 per-event payload):

```c
struct event {
    u32 event_type;
    u32 pid;
    u32 uid;
    u8  comm[16];
    u8  path[256];      // exec / openat / unlinkat
    u32 sock_family;    // AF_INET = 2 等
    u32 sock_type;      // SOCK_STREAM = 1 等
    u32 sock_protocol;
    u32 daddr_v4;       // IPv4 目的地址,network byte order
    u16 dport;          // 目的端口,network byte order
    u16 _pad;
};
```

总大小 308 字节,16 MiB ring buffer 可缓冲约 5 万条事件。

### 6.2 规则引擎

规则定义(YAML)示例:

```yaml
rules:
  - name: protected_unlink
    event_types: [unlinkat]
    match:
      path_prefix:
        - /usr/
        - /etc/
        - /bin/
        - /sbin/
        - /lib/
    action: block
    severity: critical

  - name: sensitive_path_read
    event_types: [openat]
    match:
      path_prefix:
        - /etc/shadow
        - /root/.ssh/
    action: alert
    severity: high

  - name: sensitive_keyword_read
    event_types: [openat]
    match:
      path_contains: [.env, id_rsa, id_ed25519]
    action: alert
    severity: high
```

匹配语义:

- 不同 match 字段之间为 AND 关系
- 同一 list 内字段为 OR 关系
- 规则按文件顺序遍历,first-match-wins

支持的 match 字段:`comm` `path_prefix` `path_contains` `path_exact` `family` `dest_port_in` `dest_port_not_in` `uid_min`。

支持的 action:`log` / `alert` / `block`。
支持的 severity:`info` / `low` / `medium` / `high` / `critical`。

### 6.3 LLM Investigator Agent

调用 Anthropic Messages API 的 `tool_use` 接口。默认模型 `claude-haiku-4-5`(可通过 `-llm-model` 覆盖)。

#### 6.3.1 工具集

| 工具 | 输入 schema | 实现 |
|---|---|---|
| `get_process_info` | `{pid: int}` | 读取 `/proc/PID/status` 与 `/proc/PID/cmdline`,提取 name / parent_pid / uid / cmdline |
| `recent_events_for_pid` | `{pid: int, n: int (1-50)}` | 查询 `EventHistory` 环形缓冲,返回该 PID 最近 N 条事件,按时间倒序 |
| `path_metadata` | `{path: string}` | `os.Stat` + 判断是否在 `/usr/`/`/etc/`/`/bin/` 等系统关键目录下 |

每个工具都对错误鲁棒:进程已退出、文件不存在、权限不足等情况均返回结构化错误字符串,Agent 可据此调整推理。

#### 6.3.2 Agent Loop (Plan-Execute-Synthesize)

System prompt 强制 SCAN → PLAN → EXECUTE → SYNTHESIZE 四阶段(详见 §5.8)。典型轨迹:

```
1. 用户消息: "Investigate this event: process \"rm\" pid=1234 uid=0 unlinkat path=\"/usr/bin/python3\""

2. Assistant 回复(单条消息,含 1 个 text 块 + 3 个 tool_use 块):
   - text:    "Plan: this event is destructive on the surface. I'll fetch
              parent process info, this PID's recent history, and the target
              path metadata in parallel."
   - tool_use(get_process_info,        {pid: 1234})
   - tool_use(recent_events_for_pid,   {pid: 1234, n: 20})
   - tool_use(path_metadata,           {path: "/usr/bin/python3"})

3. 用户消息(代码自动生成,3 个 tool_result 块):
   - tool_result(get_process_info,     "pid=1234 name=rm parent=1233 cmdline=\"rm -rf /usr/bin\"")
   - tool_result(recent_events_for_pid, "5 events: ... (10 previous unlinks)")
   - tool_result(path_metadata,        "kind=regular file system_critical=true")

4. Assistant 回复:
   - text:    "Confirmed: destructive rm targeting a system-critical
              binary, mid-pattern of bulk unlinks."
   - text(JSON): {"risk":94, "category":"destructive", "reason":"..."}

5. stop_reason: "end_turn" → 解析最终 JSON verdict
```

良性事件路径更短(直接跳到 step 4 出 verdict,跳过 step 2 的 plan + tool calls)。

终止条件:`stop_reason ∈ {end_turn, stop_sequence, max_tokens}`,或达到 `maxAgentTurns = 6` 上限。

返回值:`*AgentTrace { Verdict, Turns, TotalToolCalls, MaxParallelTools }`。eval 框架使用这些 telemetry 字段在汇总报告中显示"几个场景启用了并行调用、并行度最大值"等指标。

#### 6.3.3 Verdict 提取

最终输出预期为纯 JSON,但模型偶尔会包裹 Markdown fence 或加前导文字。代码做了三级容错:

1. 剥离 ``` ```json ``` / ``` ``` ``` 围栏
2. 从首个 `{` 开始截取
3. `risk` 字段强制 clamp 到 `[0, 100]`

#### 6.3.4 运行参数

| 参数 | 值 | 说明 |
|---|---|---|
| `max_tokens` | 1024 | tool_use 路径上每轮 token 上限 |
| HTTP timeout | 30 s | 整个 agent loop 的超时 |
| Worker 数 | 4 | 并发 investigation 数 |
| 队列容量 | 256 | 满则丢弃事件,不反压主路径 |
| `maxAgentTurns` | 6 | 工具调用轮数硬上限,防止失控 |

#### 6.3.5 成本估算

| 模型 | 单事件均价(估) | 14-场景 eval 全套(估) |
|---|---|---|
| `claude-haiku-4-5` | ~$0.002 | ~$0.03 |
| `claude-sonnet-4-6` | ~$0.012 | ~$0.18 |
| `claude-opus-4-7` | ~$0.06 | ~$0.85 |

价格约为单次调用的 2-3 倍(因为 tool_use 通常多 1-2 轮),换取更高质量的引证型解释。

### 6.4 Event History 缓冲

为支持调查员 Agent 的 `recent_events_for_pid` 工具,daemon 维护一份内存事件历史:

- 数据结构:append-only slice + 容量上限(默认 10 000 条),溢出时舍弃头部
- 并发:`sync.RWMutex`;写入仅由主事件循环,读取来自 LLM worker goroutine
- 查询:按 `(pid, n)` 倒序返回,或按 `(comm, event_type)` 聚合计数
- 内存占用:每条事件约 500 B,总开销 < 5 MB

历史缓冲的存在还顺带为未来的"行为基线"功能(见 §9)铺路。

### 6.5 实时 Dashboard

前端实现:

- 静态 HTML/CSS/JS,经 `//go:embed` 嵌入 daemon 二进制
- 暗色主题,monospace 字体,与终端美学一致
- WebSocket 接收事件,前端维护 `Map<id, DOMNode>` 状态
- 自动重连(断线 1 秒后重连)
- 事件列表上限 500 行,超出从尾部回收

UI 元素:

- 顶部三计数器(events / alerts / blocks)
- 类型过滤 chips(All / 五种 syscall / alerts-only / blocks-only)
- 事件列表,按严重度颜色编码,block 事件红色背景,alert 橙色边框
- LLM 评分以独立行显示,带颜色等级与悬停 tooltip

### 6.6 Eval Framework

`evals/scenarios.yaml` 定义 14 个手动标注场景,每个含:

- `event`: 待评测的 syscall 事件结构(同 `Event` 类型)
- `history` (可选):预设进 EventHistory 的上下文事件,用于测试调查员工具调用
- `expected`: `{risk_min, risk_max, category}` 期望区间

执行模式:`agent-shield -eval evals/scenarios.yaml` 不启动 eBPF/dashboard,直接顺序跑场景,输出:

- 每场景的逐条结果(PASS/FAIL、risk、category、延迟)
- 总通过率
- 按 category 的准确率
- 平均延迟
- 失败案例列表(便于回归排查)

退出码:0 当且仅当所有场景通过。

判定规则:`expected.risk_min ≤ verdict.risk ≤ expected.risk_max` 且 `verdict.category == expected.category` (若指定)。category 为空时仅检查 risk 区间。

### 6.7 Companion Agent (sysadmin-agent)

`examples/sysadmin-agent/` 为本系统的"另一面"——一个独立可运行的 AI Agent,演示被 agent-shield 监控的目标。

实现细节:

- Python 3.10+,Anthropic 官方 SDK
- 5 个 tool:`pwd` / `list_files` / `read_file` / `write_file` / `shell_exec`
- 默认模型 `claude-sonnet-4-6`(可通过 `--model` 覆盖)
- Bounded autonomy:`MAX_TURNS = 20`、`TOOL_TIMEOUT = 30 s`、tool 输出截断到 4 KB
- System prompt 显式告知 Agent "本主机由 agent-shield 监控,违规操作会被 SIGKILL"

故事闭环:

1. 用户向 Agent 发自然语言任务
2. Agent 用 tool 调查文件系统,然后 `shell_exec` 执行命令
3. 命中规则的命令被 daemon SIGKILL
4. Agent 在 `tool_result` 中看到非零 exit code,reason 推断并调整后续行为

该 Agent 本身不是 daemon 的依赖,但展示了 daemon 设计所针对的真实工作负载形态。

---

## 7. 性能与代价

### 7.1 性能目标

| 指标 | 目标 | 实测(单机 colima VM,ARM64) |
|---|---|---|
| 单事件 syscall 到 ring buffer | < 100 μs | 内核侧,未独立测量 |
| 拦截链路总延迟 | < 5 ms | rm 在第二个 unlinkat 之前死亡 |
| LLM 评分往返 | < 2 s | 1.0-1.8 s 范围,模型为 Haiku |
| Dashboard WebSocket 端到端 | < 50 ms | 同主机回环 |

### 7.2 系统开销

| 资源 | 占用 |
|---|---|
| 二进制大小 | ~12 MB(含嵌入 HTML 与 BPF 字节码) |
| 内存 | ~40 MB RSS(空闲),~80 MB(高负载) |
| BPF map | 16 MiB(ring buffer) |
| 文件描述符 | 6(5 个 tracepoint link + 1 个 ringbuf) |

---

## 8. 演示场景

`scripts/demo.sh` 自动验证以下三个场景,exit code 0 表示全部通过。

### 8.1 Demo 1: 破坏性删除(block)

- 准备 `/tmp/agent-shield-demo/` 内 10 个文件
- 触发 `rm -rf /tmp/agent-shield-demo/*`
- 预期:`rm` 进程被 SIGKILL(exit 137),9/10 文件保留

### 8.2 Demo 2: 敏感文件读取(alert)

- 准备 `/tmp/.../.env` 文件
- 触发 `cat /tmp/.../.env`
- 预期:`sensitive_keyword_read` 规则命中,事件以 alert 标记,不阻断

### 8.3 Demo 3: 正常作业(无干预)

- 触发 `ls` `cat` 等常规命令
- 预期:零 block,零 alert,所有事件以 log 通过

---

## 9. 演进路径

### 9.1 已完成(v1.0 / MVP)

- 5 个 syscall tracepoint 探针
- YAML 规则引擎与 SIGKILL 阻断
- 嵌入式 WebSocket dashboard
- LLM Investigator Agent (multi-turn tool-use loop with 3 tools)
- EventHistory 缓冲(为 Agent 工具提供查询上下文)
- Offline eval 框架(14 标注场景)
- 配套 Python Companion Agent (`examples/sysadmin-agent/`)
- 单元测试(rule engine / event history / verdict 解析)
- GitHub Actions CI(gofmt + vet + generate + build + test)

### 9.2 短期(v1.x)

- **eBPF LSM hooks**:LSM 层同步阻断,消除"近似阻断"的首 syscall 损失
- **cgroup v2 资源限制**:防止 fork bomb、内存耗尽等资源型攻击
- **更多 syscall**:`chmod`、`mmap`/`mprotect`(可执行内存写入)、`ptrace`

### 9.3 中期(v2.x)

- **行为基线建模**:对每个 Agent 实例学习正常行为,异常偏离则告警
- **多 Agent 支持**:同一主机同时监控多个 Agent 进程,事件按 cgroup 归类
- **Prometheus 指标导出**:对接现有监控栈
- **规则热加载**:不重启 daemon 切换规则

### 9.4 远期(v3.x)

- **Kubernetes DaemonSet**:作为 sidecar 部署至 Agent Pod
- **SaaS 形态**:中心化 Dashboard 聚合多机事件
- **Policy-as-Code**:OPA/Rego 集成

---

## 10. 参考资料

### 10.1 同类项目

| 项目 | 定位 |
|---|---|
| [Falco](https://falco.org/) | 容器运行时安全,业界标杆 |
| [Tetragon](https://github.com/cilium/tetragon) | Cilium 出品,现代 eBPF 可观测性框架 |
| [Tracee](https://github.com/aquasecurity/tracee) | Aqua Security 出品,威胁检测 |
| [bpftune](https://github.com/oracle/bpftune) | Oracle 出品,自适应内核调优 |

### 10.2 论文与规范

- A. Agache et al., *[Firecracker: Lightweight Virtualization for Serverless Applications](https://www.usenix.org/conference/nsdi20/presentation/agache)*, NSDI 2020.
- [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec)
- [Linux Security Modules (LSM) documentation](https://www.kernel.org/doc/html/latest/security/index.html)

### 10.3 技术参考

- [BPF CO-RE: Compile Once - Run Everywhere](https://nakryiko.com/posts/bpf-portability-and-co-re/) - Andrii Nakryiko
- B. Gregg, *Linux Observability with BPF*, O'Reilly, 2019.
- L. Rice, *Container Security*, O'Reilly, 2020.
- [cilium/ebpf](https://github.com/cilium/ebpf) Go library — 本项目所采用的 eBPF 加载器与 bpf2go 工具链

---

## 附录 A: 文档变更记录

| 日期 | 修订 | 摘要 |
|---|---|---|
| 2026-05-27 | 0.1 | 初稿 |
| 2026-05-27 | 0.2 | MVP 完成,补全实测数据与演示验证 |
| 2026-05-27 | 0.3 | 全面整理为正式规范文档体例 |
| 2026-05-27 | 0.4 | LLM 单调用升级为 Investigator Agent (tool-use multi-turn);新增 §6.4 EventHistory、§6.6 Eval、§6.7 Companion Agent;§5 增加决策 5.6 / 5.7;§3 增加目标 G6 / G7 |
| 2026-05-27 | 0.5 | Investigator Agent 升级为 Plan-Execute-Synthesize 工作流(§5.8),并行 tool calls;`runAgentLoop` 返回 AgentTrace 含 Turns/TotalToolCalls/MaxParallelTools 指标;eval summary 含 telemetry 项 |
| 2026-05-27 | 0.6 | Senior 短板补齐:reflection turn (self-critique, 影响 risk/category 时记录 VerdictRevised);SQLite 持久 AlertArchive + 第 4 个工具 `get_pid_history`;prompt caching + token/cost telemetry;A/B prompt eval(`-eval-prompts`, 多 variant 横向对比) |
