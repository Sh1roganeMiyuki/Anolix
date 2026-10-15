# 05_zygote 预热 fork 复现：从 double-fork 到共享热内存

> 研究文档系列 05 ｜ 2026-10-15
> 项目：Anolix（轻量沙箱运行时核心，Go + runc）
> 环境：WSL2 Ubuntu / 内核 6.18 / runc 1.3.4 / Go 1.27；母体宿主直跑（非 runc 容器），sudo（root）
> 本文所有数字与输出均来自本机真实运行，无推断值；推导项标注【推导】，未完成项标注【待续】。

---

## 背景

前四篇拆的都是 Anolix **已有沙箱**的机制，四个取证角度：01 = 错误码、02 = 读数、03 = 时序、04 = 视图。本篇换一件事做：给沙箱加一个**"母体预热 + 快拉 worker"的生成机制**。

动机来自 03 篇的一个数：冷启动到容器 init **483 ms**（其中 runc 段 441 ms）。这是"每造一个容器都要重付一遍"的固定成本。业界有两类**公开**的加速思路：

- **快照恢复**（如 AWS Lambda SnapStart、Firecracker snapshot）：把"初始化一次"冻成镜像，之后恢复；
- **prefork + 写时复制**（如 Android Zygote）：维持一个已加载好重型栈的母体，每个 worker 从母体 fork 一份，靠 CoW 共享只读页。

本篇实现后者。沿用前几篇的"三段链"方法，但把"声明 → 翻译 → 执法"换成 zygote 自己的三层：**协议（怎么触发）→ 生成（怎么造出隔离的 worker）→ 共享（怎么复用母体的热状态）**。

---

## 问题

| 待实证的问题 | 此前状态 |
| --- | --- |
| 从一个常驻母体 spawn 一个带完整隔离的 worker，要多久？ | 只有冷启动 483 ms（03 篇），无"温拉"数据 |
| 母体不在 PID namespace 中，clone 的返回值是不是就是宿主 PID？ | 04 篇有 NSpid 双身份的纸面结论，未在"母体无 PID ns"的场景实测 |
| worker 能否共享母体的热内存？怎么证明是"共享一份"而不是"各拷一份"？ | 无 |
| double-fork + 中间进程，在 Go 里是不是必需？ | 无 |

---

## 分析

### 装置与读法

三个二进制（均本项目自定义）：

| 二进制 | 角色 |
| --- | --- |
| `bin/zygote` | 母体守护：监听 socket、clone worker |
| `bin/spawn` | 宿主侧 client：发触发、收宿主 PID |
| `bin/worker` | worker 负载：映射共享区、自证隔离与共享 |

协议：AF_UNIX socket，帧 = `[4B 魔数 "ZYGO"][4B 大端长度][JSON]`（魔数用 ASCII，strace/抓包时肉眼可读）。【项目自定义】

启动：

```bash
# 母体（宿主直跑，需 root：clone 带 CLONE_NEW* 要 CAP_SYS_ADMIN）
sudo ./bin/zygote --socket /tmp/anolix-zygote.sock --warm 64
# client（另一终端）
sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- ./bin/worker hold 30
```

读法三原则（沿用 03 篇）：

1. `spawn 耗时` 是 **client 侧往返**（写请求 → 读响应）；母体日志两行之间是 **母体侧窗口**（更干净，不含 socket 往返）；
2. **strace 之下测到的是上界**：ptrace 给每个 syscall 收过路费，且各段放大不均（syscall 多的段被放大更狠），只看相对结构；
3. 共享与否看 **`Pss`**，不看 `Rss`（见实验三）。

### 实验一：协议与"宿主 PID 直传"

- **预期**：母体不在 PID ns 中，则 clone 的返回值直接就是 worker 的宿主 PID；worker 内部 `getpid()` 应为 1，`/proc/<host_pid>/status` 的 `NSpid` 应有两个字段。

- **数据一（NSpid 双身份）**：

  ```
  $ cat /proc/1161560/status | grep NSpid
  NSpid:  1161560 1
  ```

  宿主 PID `1161560` + ns 内 PID `1`。worker 自打印 `in-ns pid: 1`。

- **数据二（strace 母体，clone 一句带全 6 间房）**：

  ```
  1133021 clone(flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK|
            CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWNET|SIGCHLD)
  1139106 execve("/bin/busybox", ["sleep","30"], ...)
  1133021 <... clone resumed> = 1139106      ← 返回值即宿主 PID
  ```

  6 个 `CLONE_NEW*` 一个不少；clone 返回值 `1139106` 与 worker 的宿主 PID 一致。

- **结果**：
  1. "母体无 PID ns → clone 返回值即宿主 PID"成立，**无需扫 /proc 反查**——这是本设计的核心点，实测坐实。【内核固定 + 项目自定义】
  2. 6 间房由**一句 clone 原子建好**（对照 04 篇：runc 是 `unshare` 分两步建）。【内核固定】

### 实验二：从 double-fork 到直接 clone（strace 拆账）

- **预期**：一种常见写法是 double-fork + 中间进程（尤其脚本语言：`unshare()` 改调用者自己、`fork()` 不带 flags，只能借道一次性中间进程）。Go 的 `exec.SysProcAttr.Cloneflags` 能一步 clone，中间进程应可去掉；去掉后省下的正是"re-exec 一份 Go"的冷启动。

- **数据一（旧版 double-fork，strace 母体，4 段）**：

  | 段 | 区间 | 耗时 |
  | --- | --- | --- |
  | fork#1 + exec intermediate | .302244 → .307887 | 5.64 ms |
  | **intermediate 的 Go runtime 冷启动** | .307985 → .333306 | **25.32 ms** |
  | unshare(6 ns) | .333306 → .339770 | 6.46 ms |
  | fork#2 + exec worker | .340068 → .345372 | 5.30 ms |
  | 合计 | | **43.13 ms** |

  最大头是"重新启动一份 Go 进程"（25 ms），发生在 `unshare` 之前。

- **数据二（新版直接 clone，strace 母体，1 段）**：

  | 段 | 区间 | 耗时 |
  | --- | --- | --- |
  | clone(6 ns) 一句 | .858265 → .869894 | **11.63 ms** |

  没有 intermediate、没有第二次 Go 冷启动。

- **数据三（client 侧往返，无 strace）**：

  | 版本 | 样本（ms） | 中位 |
  | --- | --- | --- |
  | double-fork | 9.256 / 8.634 / 8.153 / 12.314 / 9.412 / 8.425 | ~8.5 |
  | 直接 clone | 5.008 / 7.464 / 4.943 | ~5 |

- **结果**：
  1. **中间进程不是必需**：它是"unshare 改调用者"路径的产物；Go 用 clone flags 一步到位。这不是"Go 比别的语言高级"，是运行时暴露的 API 不同（C 也能一步，runc 的 `nsexec.c` 就是 clone 带 flags）。【项目自定义】
  2. re-exec 的 Go 冷启动是**纯税**：去掉后母体侧窗口从 ~43 ms（4 段）降到 ~11.6 ms（1 句），client 侧中位从 ~8.5 ms 降到 ~5 ms。【测量】
  3. **代价**：worker 变成母体的直接子进程，收尸责任回到母体（旧版靠 intermediate 退出触发 reparent）。实现里用一个后台 goroutine `cmd.Wait()` 兜住。【项目自定义】

### 实验三：共享热内存（memfd + MAP_SHARED）

- **预期**：worker 应共享母体已写好的热数据；若是"共享一份"，则 `Pss` 应按共享份数摊薄（N 个 worker 各约 1/N），且整块落在 `Shared_*` 而非 `Private_*`。

- **数据（两个 worker 各自打印的 smaps，64 MB 共享区）**：

  | 指标 | Worker 1 (1161537) | Worker 2 (1161560) |
  | --- | --- | --- |
  | Size | 65540 kB | 65540 kB |
  | Rss | 65540 kB | 65540 kB |
  | **Pss** | **21846 kB** | **16385 kB** |
  | Shared_Clean | 0 kB | 0 kB |
  | **Shared_Dirty** | **65540 kB** | **65540 kB** |
  | Private_Clean | 0 kB | 0 kB |
  | Private_Dirty | 0 kB | 0 kB |

  校验：`magic=OK`、`pattern 校验 OK（全部 67108864 字节与母体写入逐字节一致）`。

- **结果**：
  1. **真共享，不是各拷一份**：`Shared_Dirty = Size = 65540 kB`（整块），`Private_* = 0`。【内核固定】
  2. **`Pss = 65540 / N`**：Worker 1 的 21846 ≈ 65540/3，Worker 2 的 16385 ≈ 65540/4。分母不同不是噪声，是**动态证据**——读数时刻存活的 worker 数不同（`hold 30` 让 worker 累积），每多一个 worker，`Pss` 自动摊薄一份。【推导，基于 Pss 定义】
  3. **`Rss` 骗人、`Pss` 说真话**：每个 worker 的 `Rss` 都报 65540 kB（看着像各自独占 64 MB），但物理上只有一份；`Pss` 才把它摊成 64/N。看共享必须看 Pss。【内核固定】
  4. **为什么落在 `Shared_Dirty` 而不是 `Shared_Clean`**：母体是用 `write()` 写 memfd 的，页在 page cache 里是脏的；memfd 无后端存储、脏位不回写清除 → `MAP_SHARED` 映射到脏页 → 记 `Shared_Dirty`。【内核固定，推导】

### 实验四：为什么不是 fork-CoW（Go 的边界）

- **预期**：经典 zygote（如 Android）靠 `fork()` 让 worker CoW 继承母体整个地址空间（含已加载的运行时/模型）。Go 能否照搬？

- **数据（strace 里 clone 的 flags）**：两次 clone 都带 `CLONE_VM|CLONE_VFORK` —— Go 的 `os/exec` 用的是 **vfork**：母体被挂起直到 worker `execve`，worker 随即 exec 成新程序。

- **结果**：
  1. **Go 里 fork-continue 是地雷**：runtime 多线程，fork 后子进程只剩一个线程，调度器/GC/锁全坏；"fork 后不 exec、原地续行"会随机死锁/崩溃。所以本项目**没有**走 fork-CoW。【内核固定 + 语言运行时】
  2. **vfork 正是"要 exec"的症状**：真 zygote（子进程原地续行、继承活进程状态）不能用 vfork。本项目 worker 仍 exec，因此**只共享数据 blob，不共享母体的"活进程状态"**。【项目自定义，已知局限】
  3. **改用共享内存达成同一目标**：对"只读热状态"（模型权重、词表、预热缓存），`memfd + MAP_SHARED` 其实**比 fork-CoW 更优**——CoW 在任一 worker 首次写时会把整页私有化，共享内存则始终共享、永不复制。【项目自定义】

---

## 数据对比

三版演进（本篇核心产出）：

| 版本 | 生成机制 | 热状态共享 | 母体侧窗口(strace) | client 往返中位 |
| --- | --- | --- | --- | --- |
| v1 double-fork | re-exec 中间进程 + unshare + fork | 无（worker exec，且不共享） | ~43 ms（4 段） | ~8.5 ms |
| v2 直接 clone | `Cloneflags` 一句 clone | 无 | ~11.6 ms（1 句） | ~5 ms |
| **v3 共享热内存** | 同 v2 + `ExtraFiles` 传 memfd | **memfd + MAP_SHARED** | 同 v2 | ~2.5–4 ms |

关键实测锚点：

| 结论 | 证据 |
| --- | --- |
| 宿主 PID 直传 | `NSpid: 1161560 1`；clone 返回值 = 宿主 PID |
| 6 间房一句建好 | strace `clone(...CLONE_NEWNS\|NEWCGROUP\|NEWUTS\|NEWIPC\|NEWPID\|NEWNET...)` |
| re-exec 是税 | v1 的 25 ms Go-init 段在 v2 消失 |
| 真共享热内存 | `Shared_Dirty=65540`、`Private_*=0`、`Pss=65540/N` |

---

## 结论与启示

### 1. 结论

1. **宿主 PID 直传成立**：母体不在 PID ns 中，clone 返回值即宿主 PID，worker 内 `getpid()=1`、`NSpid` 两字段——本设计的核心点实测坐实；
2. **中间进程可去**：double-fork 是"unshare 改调用者"路径的产物；Go 用 `Cloneflags` 一句 clone 原子建好 6 间房，省掉 re-exec 的 ~25 ms Go 冷启动；
3. **热内存可共享**：`memfd + MAP_SHARED` 让 N 个 worker 共用一份物理页，`Pss = 65540/N`、`Shared_Dirty` 整块、`Private_*` 为 0；
4. **不走 fork-CoW 是语言边界**：Go 多线程 runtime 下 fork-continue 不安全，vfork+exec 是症状；共享内存是 Go 原生、且对只读热状态更优的替代。

### 2. 教训

- **strace 抓对进程才有意义**：client 侧 trace 看不到母体的 clone/unshare（两个进程），第一次抓错对象，白测一轮；
- **`Rss` 会骗人**：共享场景下每个进程 `Rss` 都报满额，`Pss` 才按份摊薄——判断"共享 vs 各拷一份"只看 Pss + Shared/Private 分栏；
- **`Shared_Clean=0` 不等于没共享**：memfd 被 `write()` 过是脏页，落 `Shared_Dirty`；打印证据要把 Dirty 两栏也带上，否则会误判；
- **实现税 ≠ 机制成本**：v1 的 43 ms 里最大头是"重启一份 Go"（自己引入的），不是 clone/unshare 本身——拆账要拆到"哪段是机制、哪段是实现"；
- **数字要脱掉 strace、跑够样本**：client 往返单次 1.3–12 ms 抖动大，只能报中位、且注明样本量。

---

## 下一步

| # | 项 | 目的 | 状态 |
| --- | --- | --- | --- |
| 1 | **state.json 收养** | 让 runc `list/kill/delete` 管得到 worker（运行时纳管，尚未做） | 待执行 |
| 2 | 母体进 runc 容器 | 用 `zygote/spec.go` 生成 bundle，对齐"母体是容器"的形态 | 装置已写，待跑 |
| 3 | 延迟稳态数 | 脱掉 strace、跑 ≥50 次取 p50/p95；换重型 payload 让"省掉的初始化"有意义 | 待执行 |
| 4 | seccomp / cgroup 继承 | 母体 clone 前装 seccomp（worker 继承，只能加严）；为 worker 建叶子 cgroup 迁移 | 待执行 |
| 5 | rootless | 加 `CLONE_NEWUSER` + uid map，母体免 sudo | 待执行 |

---

## 附录：命令

```bash
# 构建
go build -o bin/zygote ./cmd/zygote
go build -o bin/spawn  ./cmd/spawn
go build -o bin/worker ./cmd/worker

# 母体（64MB 共享区）
sudo ./bin/zygote --socket /tmp/anolix-zygote.sock --warm 64

# spawn（worker 打印落在母体终端）
sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- ./bin/worker hold 30

# 验证隔离
cat /proc/<host_pid>/status | grep NSpid          # 两个字段：<host> 1

# 验证共享（worker 自打印，或宿主侧读）
cat /proc/<host_pid>/smaps | grep -A20 memfd       # Shared_Dirty≈整块、Pss=Size/N

# strace 母体（拆生成账；-f 跟子进程）
sudo strace -f -tt -o /tmp/m.trace -p <mother_pid>
grep -E 'clone|execve|unshare' /tmp/m.trace
```

源码参照位置：

- `zygote/protocol.go`（帧协议）、`zygote/spawn.go`（`Cloneflags` 一句 clone + 收尸）、`zygote/warm.go`（memfd 创建/映射 + smaps 解析）、`zygote/spec.go`（母体 OCI spec）
- `cmd/zygote/main.go`（母体）、`cmd/spawn/main.go`（client）、`cmd/worker/main.go`（worker 负载）
- `docs/zygote-design.md`（架构与演进）；旧 double-fork 版见 git 历史
