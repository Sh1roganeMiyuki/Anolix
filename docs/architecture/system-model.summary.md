# system-model.summary.md — Anolix 当前态架构解读

> 由「架构可视化」插件生成：场景技能 `system-modeler`，格式基础 `c4model`（DSL）+ `graphviz`（DOT）。
> 配套产物：[`system-context.structurizr.dsl`](system-context.structurizr.dsl)（C4 三视图）、[`package-dependency.dot`](package-dependency.dot)（包依赖）、[`architecture-model.json`](architecture-model.json)（结构化模型）、[`system-model.evidence.md`](system-model.evidence.md)（证据索引）。

## 一句话定位

Anolix 是一个**沙箱外壳**：把安全策略（policy）翻译成 OCI 配置，并管理容器生命周期——隔离机制本身由 runc 与 Linux 内核提供，仓库不重造。

## 系统边界与主要部分

- **边界内**：`cmd/anolix`（CLI 启动器）、`config`（策略解析/校验）、`launcher`（OCI spec 生成 + 生命周期）、`cmd/probe`/`cmd/sysc`/`cmd/rawfilter`（沙箱内工具）、`scripts/`（构建、三世界实验、可视化）。
- **边界外**：`runc`（OCI 运行时，通过 PATH 查找并 exec）、Linux 内核（namespaces / seccomp BPF / cgroups 的实际执行者）。
- **静态产物**：`examples/policy.json`（示例策略）、`rootfs/`（由脚本生成、被 git 忽略的容器根文件系统）。

## 关键关系（C4 视角）

1. 开发者 → **anolix CLI**：`anolix run --policy … --rootfs … -- /probe`。
2. CLI 内部：`cmd/anolix` → `config`（取策略）→ `launcher`（`New` + `Run(ctx)`）；`launcher` 反向依赖 `config` 的校验与取值（`Validate` / `Effective*`）。
3. 启动链路：`launcher` 生成 bundle（config.json + rootfs）后 **exec `runc run`**；超时/中断先 SIGTERM 再兜底强杀并 `runc delete --force`。
4. 隔离落地：`runc` 请求内核创建 namespaces、装载 seccomp BPF、应用 cgroup 设备规则，并以容器 init 执行 `/probe`（或实验用 `/sysc`）。
5. 实验与可视化：`syscall-lab.sh` 做宿主/沙箱对照；`skscope.py`、`kstate.py` 启动真实沙箱抓取 `/proc` 现场。

## 证据强度

- 全部节点与边为 **high**（代码原文级证据，sourceRefs 可逐条复核）；未采集运行时遥测，运行期关系以配置与文档为依据（见证据索引「已知局限」第 4 条）。

## 未知与验证缺口

- README 尚未覆盖 `cmd/sysc`、`cmd/rawfilter`、`syscall-lab.sh`（文档漂移）。
- `scripts/skscope.py`、`kstate.py`、`cmd/rawfilter/` 尚未入库。
- 本地 `rootfs/` 内的 busybox/sh 等超出 `mkrootfs.sh` 产物，属实验残留。

（完整验证任务清单见 [`system-model.evidence.md`](system-model.evidence.md)。）

## 阅读顺序与预览方式

1. 先看 `system-context.structurizr.dsl` 的 SystemContext 视图 → Containers 视图 → CliComponents 视图。
2. 再看 `package-dependency.dot`：全仓库唯一第三方依赖是 `runtime-spec`；三个探针工具彼此独立（仅标准库）。
3. 需要逐条核对时打开 `architecture-model.json` 与证据索引。
4. **预览**：在 Qoder 中打开 `.structurizr.dsl` 文件由插件的 Structurizr DSL viewer 渲染；打开 `.dot` 文件由 DOT viewer 渲染。文件本身是唯一事实源，预览为派生视图。

## 下一步路由建议（按问题类型）

| 下一步问题 | 建议技能 |
| --- | --- |
| 一次 `anolix run` 的完整时序（准备 → runc → seccomp → 探针 → 退出码透传） | `flow-visualizer` |
| rootless 状态目录、bundle 生命周期、运行环境的部署视图 | `deployment-topology-analyzer` |
| 该架构的风险、技术债与质量属性评估 | `risk-quality-reviewer` |
| 防止模型随代码漂移（sourceRefs 复核 / 增量 diff） | `architecture-health` |
| 规划 shim、二阶段 seccomp 等演进目标 | `evolution-planner` |

## 维护说明

本模型为**手工编写的当前态快照**（插件不提供确定性抽取器）；代码变更后，按 `architecture-model.json` 中的 `sourceRefs` 逐条复核并更新对应视图，保持节点/边的稳定 ID 不变。