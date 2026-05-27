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

### 6.3 LLM 风险评分器

调用 Anthropic Messages API,默认模型 `claude-haiku-4-5`。

System Prompt(节选):

```
You are a security auditor for an AI agent's runtime behavior.

Given a single syscall event observed from an AI agent process, output a JSON object with:
- risk: integer 0-100 (severity of the action; 0=safe, 100=catastrophic)
- category: one of "destructive" | "exfiltration" | "recon" | "egress" | "benign"
- reason: 1 sentence explaining what is happening and why it is (or is not) risky

Respond with ONLY the JSON object, no markdown fences, no preamble.
```

参数:
- `max_tokens`: 200
- HTTP timeout: 20 s
- Worker 数: 4
- 队列容量: 256
- 队列满策略: 丢弃(避免拦截链路被反压)

成本估算(基于 Haiku 4.5 公开定价):每次评分约 $0.0008,典型 1 小时 demo session 触发 5-30 次评分,总成本不超过 $0.05。

### 6.4 实时 Dashboard

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
- 异步 LLM 风险评分
- 单元测试与 GitHub Actions CI

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
