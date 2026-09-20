# system-model.evidence.md — 证据索引（当前态）

> 场景技能：`system-modeler`｜格式基础：`c4model`（Structurizr DSL）、`graphviz`（DOT）
> 采集日期：2026-09-20 ｜ 采集方式：直接阅读仓库代码、脚本、示例与 README，逐文件核对行号
> 视图状态：**全部为 current（当前态）**；本文件只记录事实与置信度，不做风险评审（评审请路由 `risk-quality-reviewer`）

## 置信度标签

| 标签 | 含义 |
| --- | --- |
| high | 直接证据：代码、脚本、配置原文（本模型全部节点与边均为 high） |
| medium / low / unknown | 多条间接信号一致 / 命名推断 / 未验证（本模型未使用） |

## 节点证据

| 节点 ID | 标签 | 证据类型 | sourceRefs | 置信度 |
| --- | --- | --- | --- | --- |
| person.developer | 开发者 / 学习者 | document | `README.md:38-47` | high |
| system.anolix | Anolix 沙箱运行时 | document | `README.md:3-6` | high |
| container.cli | anolix CLI | code + document | `cmd/anolix/main.go:24-92`、`README.md:99-110` | high |
| container.probe | probe 探针 | code + config | `cmd/probe/main.go:1-14`、`scripts/mkrootfs.sh:20` | high |
| container.sysc | sysc 系统调用探针 | code | `cmd/sysc/main.go:1-14`、`cmd/sysc/raw_amd64.s:1-8` | high |
| container.rawfilter | rawfilter 原始过滤器实验 | code | `cmd/rawfilter/main.go:1-17` | high |
| container.lab-build | 构建与实验脚本 | code | `scripts/mkrootfs.sh:1-5`、`scripts/syscall-lab.sh:2-7` | high |
| container.lab-visual | 可视化脚本（本地未入库） | code | `scripts/skscope.py:1-18`、`scripts/kstate.py:1-16` | high |
| component.cli-main | CLI 入口（cmd/anolix） | code | `cmd/anolix/main.go:24-47`、`cmd/anolix/main.go:54-84` | high |
| component.config-pkg | config 包 | code | `config/config.go:104-142`、`config/config_test.go` | high |
| component.launcher-pkg | launcher 包 | code | `launcher/spec.go:25-92`、`launcher/launcher.go:162-212`、`launcher/launcher_test.go` | high |
| external.runc | runc（OCI 运行时） | code + document | `README.md:12`、`launcher/launcher.go:150-160` | high |
| external.kernel | Linux 内核 | code + document | `launcher/spec.go:27-48`、`README.md:96-97` | high |
| artifact.policy-sample | 示例 policy | config | `examples/policy.json:1-74` | high |
| artifact.rootfs | 最小 rootfs（构建产物） | code + config | `scripts/mkrootfs.sh:16-22`、`.gitignore:7-8` | high |

## 边证据

| 边 ID | 关系 | 证据类型 | sourceRefs | 置信度 |
| --- | --- | --- | --- | --- |
| edge.developer-to-anolix | uses（CLI） | document | `README.md:38-47` | high |
| edge.labbuild-to-cli | calls（Bash） | code | `scripts/syscall-lab.sh:43-50` | high |
| edge.labbuild-to-sysc | calls（宿主直跑对照） | code | `scripts/syscall-lab.sh:39-41` | high |
| edge.labbuild-to-probe | builds（Go build） | code | `scripts/mkrootfs.sh:20` | high |
| edge.labbuild-to-rootfs | builds（file） | code | `scripts/mkrootfs.sh:16-19` | high |
| edge.labvisual-to-cli | calls（Python） | code | `scripts/skscope.py:8`、`scripts/kstate.py:12` | high |
| edge.climain-to-configpkg | calls（in-process） | code | `cmd/anolix/main.go:54-62` | high |
| edge.climain-to-launcherpkg | calls（in-process） | code | `cmd/anolix/main.go:64-84` | high |
| edge.launcherpkg-to-configpkg | depends-on（in-process） | code | `launcher/launcher.go:71-77`、`launcher/spec.go:77-92` | high |
| edge.launcherpkg-to-runc | calls（CLI/exec） | code | `launcher/launcher.go:150-160`、`launcher/launcher.go:186-196` | high |
| edge.cli-to-runc | calls（CLI/exec，容器级） | code | `launcher/launcher.go:150-160` | high |
| edge.climain-to-policy | reads（file/JSON） | code | `cmd/anolix/main.go:55-62`、`config/config.go:89-100` | high |
| edge.launcherpkg-to-rootfs | reads（file/dir） | code | `launcher/launcher.go:255-288` | high |
| edge.runc-to-kernel | calls（syscalls） | code + document | `launcher/spec.go:27-34`、`README.md:96-97` | high |
| edge.runc-to-probe | executes（container-init） | document | `README.md:38-47` | high |
| edge.runc-to-sysc | executes（container-init） | code | `scripts/syscall-lab.sh:44-45` | high |
| edge.probe-to-kernel | calls（syscalls） | code | `cmd/probe/main.go:96-100`、`cmd/probe/main.go:170-189` | high |
| edge.sysc-to-kernel | calls（syscalls） | code | `cmd/sysc/main.go:95-102` | high |
| edge.rawfilter-to-kernel | configures（prctl） | code | `cmd/rawfilter/main.go:105-115` | high |

## 已知局限与验证任务（validation tasks）

1. **文档漂移**：README 的「项目结构」一节（`README.md:99-110`）未描述 `cmd/sysc`、`cmd/rawfilter`、`scripts/syscall-lab.sh`。
   → 验证任务：确认是否更新 README，使文档与已入库代码一致。
2. **本地未入库文件**：`scripts/skscope.py`、`scripts/kstate.py`、`cmd/rawfilter/` 在工作区存在但未纳入 git（`git status` 显示 untracked）。
   → 验证任务：决定哪些纳入版本控制；模型已按现状标注。
3. **rootfs 现状超出脚本产物**：`scripts/mkrootfs.sh` 只生成 `probe` 与 `tmp`，而本地 `rootfs/` 还含 `busybox`、`sh`、`sysc`、`rawfilter`（实验残留；`/rootfs/` 被 `.gitignore` 忽略，属本地产物，非仓库架构）。
   → 验证任务：确认为实验残留或补充构建脚本。
4. **运行时遥测未采集**：本模型未实际运行沙箱抓取运行期证据；`external.runc → external.kernel` 等运行期关系以配置（OCI spec 字段）与文档为依据。
   → 验证任务：如需运行期实测证据，用 `scripts/skscope.py` / `kstate.py` 采集后由 `architecture-health` 复核。
5. **计划中形态未建模**：仓库内没有关于 shim / 二阶段 seccomp / 矩阵 runner 的代码或文档证据。
   → 保持不建模；如出现正式方案，应由 `evolution-planner` 生成 target 视图后再纳入。

## 模型完整性说明

- 结构证据（节点/边）与行为证据已分离：本模型的边全部来自代码中的调用/执行/读取语句或文档中的明确操作说明。
- 单 package 语义映射的落点：policy → OCI seccomp 配置（含 `defaultErrnoRet`）的映射见 `launcher/spec.go:77-92`。
- 本文件不含质量评审结论、改进建议与健康度检查——按 `system-modeler` 技能边界，分别路由 `risk-quality-reviewer`、`evolution-planner`、`architecture-health`。