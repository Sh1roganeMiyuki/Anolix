# Zygote 预热 Fork 机制：架构设计文档

> 本文件随代码实现同步更新，记录架构决策与演进。
> 动机：削减容器冷启动成本（03 篇实测到容器 init 483 ms），借鉴业界公开的
> Android Zygote「prefork + 写时复制」与 serverless 快照恢复两类加速思路。

---

## 一、整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│  宿主                                                            │
│                                                                  │
│  ┌──────────┐    AF_UNIX     ┌──────────────────────────────┐   │
│  │ spawn    │───────────────►│ zygote mother (常驻守护)      │   │
│  │ client   │◄───────────────│                              │   │
│  └──────────┘   host PID     │  持有 warm memfd（热数据）    │   │
│                              │  不在 PID namespace 中        │   │
│                              └──────────┬───────────────────┘   │
│                                         │                        │
│                    clone(CLONE_NEW* 6 间房) + ExtraFiles(memfd)   │
│                    （一步到位，无中间进程）                        │
│                                         │                        │
│                                         ▼                        │
│                              ┌──────────────────────┐            │
│                              │ worker               │            │
│                              │ PID=1 in new PID ns  │            │
│                              │ mmap memfd MAP_SHARED│            │
│                              │ → 共享母体热数据      │            │
│                              └──────────────────────┘            │
│                                                                  │
│  worker 是 mother 的直接子进程 → mother 用后台 goroutine Wait 收尸 │
└─────────────────────────────────────────────────────────────────┘
```

> **演进说明**：
> - v1（double-fork + unshare，re-exec 一个 Go 中间进程）：strace 实测中间进程 Go 冷启动约 25ms，是纯税。已入 git 历史。
> - v2（直接 clone）：`SysProcAttr.Cloneflags` 一步 clone 出带 6 间房的 worker，去掉中间进程。
> - v3（共享热内存，当前）：memfd + MAP_SHARED，worker 共享母体热数据。

---

## 二、文件结构与职责

```
zygote/
  protocol.go     通信协议：SpawnRequest/Response + 帧编解码
  spawn.go        核心机制：SysProcAttr.Cloneflags 一步 clone 出带 6 间房的 worker
  warm.go         共享热内存：memfd 创建/写入 + worker 侧 mmap + smaps 证据
  cgroup.go       资源围栏：per-worker 叶子 cgroup + clone3(CLONE_INTO_CGROUP) 出生即在册
  spec.go         母体容器 OCI spec 生成（无 PID ns、有 caps、无 seccomp）

cmd/
  zygote/main.go  母体守护进程入口（创建共享 memfd）
  worker/main.go  worker 负载：映射共享区、校验、打印共享证据
  spawn/main.go   宿主侧 spawn 客户端
```

---

## 三、协议设计

### 3.1 传输层

- AF_UNIX socket（母体监听，client 连接）
- 帧格式：`[4B 魔数 "ZYGO"] [4B 大端长度] [JSON payload]`
- 响应格式：`[4B 大端长度] [JSON payload]`（无魔数，简化）

### 3.2 请求/响应

```json
// 请求
{
  "binary": "/path/to/bin/worker",
  "args": ["hold", "30"],
  "env": ["PATH=/bin"],
  "cwd": "/",
  "worker_id": "worker-1"
}

// 响应（成功）
{"host_pid": 12345}

// 响应（失败）
{"host_pid": -1, "error": "clone 失败: operation not permitted"}
```

### 3.3 设计选择

| 选择 | 取值 | 原因 |
|---------|--------|---------|
| 魔数 | "ZYGO"（4 字节 ASCII） | 抓包/strace 时肉眼可读，便于调试 |
| 编码 | 长度前缀 + JSON | 自描述、易扩展，性能非瓶颈 |
| 返回 | 宿主 PID | client 拿到即可 kill / 读 /proc 管理 worker |

---

## 四、Worker 生成机制：从 double-fork 到直接 clone

### 4.1 为什么 double-fork + 中间进程是一种常见写法

很多实现（尤其脚本语言）造隔离 worker 时会走"中间进程 + double-fork"，这是被机制逼出来的：

1. **unshare 改的是调用者自己**：`unshare(CLONE_NEWNS/UTS/IPC/NET/CGROUP)` 让调用进程**立即**进入新 ns；`unshare(CLONE_NEWPID)` 让调用进程的**下一个子进程**成为新 PID ns 的 1 号。母体不能去 unshare 自己（否则母体被污染）→ 必须借道一个一次性中间进程。
2. **`fork()` 不带 flags**：像 Python 的 `os.fork()` 没法一步 clone 出带 ns 的孩子，只能 `unshare()` + `fork()` 两步 → 中间进程是自然结果。
3. **顺带拿到 reparent**：中间进程退出后 worker 被 reparent，母体免收尸。

### 4.2 Go 为什么能一步 clone（本实现）

Go 的 `exec.Cmd.SysProcAttr.Cloneflags` 把 flags 直接透给 `clone(2)`：

```go
cmd.SysProcAttr = &syscall.SysProcAttr{
    Cloneflags: syscall.CLONE_NEWNS | syscall.CLONE_NEWPID |
        syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC |
        syscall.CLONE_NEWNET | syscall.CLONE_NEWCGROUP,
    Setsid: true,
}
cmd.Start()
hostPID := cmd.Process.Pid  // 母体不在 PID ns → 这就是宿主 PID
```

- 内核在 clone 那一刻**原子建好 6 间房**，孩子直接是 pid 1 → 不需要 unshare、不需要中间进程。
- 这不是"Go 比别的语言高级"，是**运行时暴露的 API 不同**：C 也能一步（runc 的 `nsexec.c` 就是 clone 带 flags）；脚本语言要走一步 clone 得下到 ctypes/preexec_fn，不惯用。
- **实测坐实**（strace 母体）：`clone(flags=CLONE_VM|CLONE_PIDFD|CLONE_VFORK|CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWNET|SIGCHLD)` → 6 个 `CLONE_NEW*` 一个不少。

### 4.3 演进：旧版 re-exec 的税

旧 double-fork 版为绕开"Go 多线程不能安全 raw fork"，re-exec 了一个 Go 中间进程。代价（strace 实测）：

| 段 | 时长(strace 下) | 性质 |
|---|---|---|
| fork#1 + exec intermediate | ~5.6ms | 可省 |
| **intermediate 的 Go runtime 冷启动** | **~25ms** | **纯税，可省** |
| unshare(6ns) | ~6.5ms | 新版由 clone flags 承担 |
| fork#2 + exec worker | ~5.3ms | 保留 |

新版砍掉中间进程 → 那 ~25ms 的 Go-init 税直接消失。母体侧窗口从 ~43ms（strace 下，4 段）降到 ~11.6ms（1 句 clone）。

### 4.4 新版时序图

```
mother                              worker
  │                                   │
  │── clone(CLONE_NEW* 6 间房) ──────►│
  │   + ExtraFiles(memfd→fd3)         │── 出生即 pid 1
  │   (cmd.Start，一步)                │── exec worker
  │◄── cmd.Process.Pid = host PID ────│── mmap fd3 MAP_SHARED
  │                                   │
  │── response: {host_pid} ── client  │── 独立运行
  │   (后台 goroutine: cmd.Wait 收尸)  │
```

### 4.5 代价：收尸责任回到母体

旧版靠中间进程退出触发 reparent，母体不用管 worker 死活。新版 worker 是母体的**直接子进程**：

- 母体必须自己 `Wait`，否则 worker 退出后留僵尸。
- 实现：`SpawnWorker` 里起一个后台 goroutine `cmd.Wait()`（见 `spawn.go`）。
- 这是小账（一个 goroutine），换掉的是 ~25ms 的 Go-init 税。

### 4.6 一个结构性事实：vfork

strace 里 clone 带 `CLONE_VM|CLONE_VFORK` = Go 的 os/exec 用 **vfork**：母体被挂起直到 worker `execve`。所以：

- "spawn 延迟"里天然含了 worker 的 execve。
- **vfork 正是"要 exec"的症状**——真正的 no-exec zygote（子进程原地续行）不能用 vfork，得用普通 fork（才有 CoW）。这也是为什么共享热内存走了 memfd 而不是 fork-CoW（见第五章）。

---

## 五、共享热内存（memfd + MAP_SHARED）

### 5.1 为什么不用 fork-CoW

zygote 的经典做法（如 Android Zygote）是 `fork()`：子进程 CoW 复制母体地址空间，天然共享母体已加载的运行时与模型页。

**Go 里这条路是地雷**：runtime 多线程，fork 后子进程只剩一个线程，调度器/GC/锁全坏；"fork 后不 exec、原地续行"会随机死锁/崩溃。所以本实现改用**共享内存**达成同一目标。

### 5.2 机制

```
母体启动 → CreateWarmMemfd(size)：memfd_create + 写 [magic|size|pattern]
        → 持有 *os.File（保持 memfd 存活）
spawn 时 → cmd.ExtraFiles = [warmFile] → worker 侧固定拿到 fd 3
worker  → MapWarm(3)：fstat 取大小 → mmap(PROT_READ, MAP_SHARED)
        → 校验 magic + 逐字节 pattern → 读 smaps 看共享页
```

- **memfd**：匿名文件，活在内存里，不占文件系统路径；所有引用关闭即自动回收。
- **MAP_SHARED + 同一个 memfd**：母体与所有 worker 映射到**同一批物理页**，零拷贝。
- **fd 传递**：靠 `ExtraFiles`（exec 继承 fd 3），不需要 SCM_RIGHTS，也不需要文件路径。
- **memfd 跨 namespace**：fd 不依赖挂载 ns，worker 在新 mount ns 里照样能 mmap。

### 5.3 共享内存 vs fork-CoW

| | fork-CoW（Android Zygote） | 共享内存（本实现） |
|---|---|---|
| 共享粒度 | 母体整个地址空间 | 显式放进 memfd 的那块 |
| 写时行为 | 任一 worker 写 → 复制整页（私有化） | MAP_SHARED 写 → 所有 worker 立即可见 |
| 只读热状态 | 共享，但一写就分裂 | **始终共享，永不复制** |
| Go 可行性 | 不安全（多线程 runtime） | 安全、原生 |

对"只读热状态"（模型权重、词表、预热缓存），共享内存其实**比 CoW 更优**——CoW 在首次写时会把整页私有化，共享内存则一直共享。

### 5.4 验证证据（worker 自打印）

- `in-ns pid=1` + `NSpid: <host> 1` → PID ns 隔离
- `pattern 校验 OK` → 读到的确实是母体写入的数据（逐字节）
- `smaps` 的 `Shared_Dirty ≈ 整个区`、`Private_* ≈ 0` → **物理页真共享**
- `Pss = 区大小 / N`（N = 并发 worker 数）→ 按共享份数摊薄

> 判读关键：memfd 被 `write()` 过是脏页，`MAP_SHARED` 映射后落 `Shared_Dirty`（不是 `Shared_Clean`）。`Rss` 每个 worker 都报满额（看着像独占），`Pss` 才按份摊薄——看共享必须看 Pss + Shared/Private 分栏。

---

## 六、母体容器 Spec 设计

### 6.1 与普通沙箱的差异

母体是"受信基础设施"，不是"被隔离的不可信负载"：

| 维度 | 普通沙箱 | 母体 | 原因 |
|------|---------|------|------|
| PID ns | 有 | **无** | clone 返回值 = 宿主 PID |
| Caps | 清空 | CAP_SYS_ADMIN | clone 带 CLONE_NEW* 需要 |
| Seccomp | 严格白名单 | **关闭** | 需要全量 syscall |
| NNP | true | **false** | caps 需要 |
| MNT/UTS/IPC/NET/CGROUP | 有 | 有 | 母体自身仍需部分隔离 |

### 6.2 Socket 通信路径

```
宿主侧：  <socketDir>/spawn.sock     ← client 连接这里
容器内：  /run/spawn/spawn.sock      ← 母体监听这里
          ↑ 同一个文件（bind-mount）
```

### 6.3 启动方式

```bash
# 1. 构建
go build -o bin/zygote ./cmd/zygote
go build -o bin/spawn  ./cmd/spawn
go build -o bin/worker ./cmd/worker

# 2. 宿主直跑母体（需 root：clone 带 CLONE_NEW* 要 CAP_SYS_ADMIN）
sudo ./bin/zygote --socket /tmp/anolix-zygote.sock --warm 64

# 3. Spawn 一个共享热内存的 worker
sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- ./bin/worker hold 30

# 4. 验证
cat /proc/<host_pid>/status | grep NSpid    # 两个字段：宿主 PID + 1
cat /proc/<host_pid>/smaps | grep -A20 memfd # Shared_Dirty ≈ 整个区
```

> 母体进 runc 容器（用 `zygote/spec.go` 生成 bundle）是后续迭代；当前实验走宿主直跑最省事。

---

## 七、隔离与资源围栏（Namespace + cgroup）

Worker 获得的 6 间房（由 `clone` 的 `CLONE_NEW*` flags 一步创建）：

| Namespace | Flag | Worker 内效果 |
|-----------|------|--------------|
| Mount | CLONE_NEWNS | 独立挂载树（继承母体的副本） |
| PID | CLONE_NEWPID | worker = PID 1；其子进程 = 2, 3… |
| UTS | CLONE_NEWUTS | 独立主机名 |
| IPC | CLONE_NEWIPC | 独立共享内存/消息队列 |
| Network | CLONE_NEWNET | 无网络（只有 down 的 loopback） |
| Cgroup | CLONE_NEWCGROUP | 独立 cgroup 视图 |

验证手段：
- 宿主侧 `cat /proc/<host_pid>/status | grep NSpid` → 两个字段（已实测：`NSpid: 1161560 1`）
- 母体 strace → `clone(flags=...CLONE_NEWNS|CLONE_NEWCGROUP|CLONE_NEWUTS|CLONE_NEWIPC|CLONE_NEWPID|CLONE_NEWNET...)`（已实测 6 个全带）
- worker 内 `getpid()` 返回 1（worker 自打印）

### 7.1 cgroup 资源围栏（per-worker 叶子）

每个 worker 一个专属叶子 cgroup（`/sys/fs/cgroup/anolix-<id>`），可设 `memory.max` / `pids.max` / `cpu.max`。

**关键：用 `clone3(CLONE_INTO_CGROUP)` 消掉启动空窗。** Go 的 `SysProcAttr.UseCgroupFD + CgroupFD` 底层就是它——worker **一出生就落在叶子里**，而不是"先 clone 再写 `cgroup.procs` 迁移"（那样两步之间 worker 已能跑却不受限）。这与"出生就带 ns"是**同一个套路**：不是事后补，是出生就带。

- 归属是"户口"：由**母体**（外部）建叶子、写限额、传 fd；worker 自己够不着宿主 cgroup 层级。
- 生命周期：worker 退出 → 收尸 goroutine `Destroy()`（关 fd + rmdir 叶子），防泄漏。
- worker 自带 `CLONE_NEWCGROUP` → 它自己看到的是 ns 根（`/`），**验证要从宿主侧**看 `/sys/fs/cgroup/anolix-<id>/`。

---

## 八、已知局限与后续迭代

| 局限 | 影响 | 后续方案 |
|------|------|---------|
| ~~worker 不共享母体热内存~~ | ✅ 已用 memfd+MAP_SHARED 解决（见第五章） | 只读热状态已共享；若要共享母体"活对象"（非 blob），仍需 no-exec fork（Go 不安全） |
| 无 state.json 注册 | runc list/kill/delete 管不到 worker | 实现收养逻辑（写 runc state 目录） |
| 母体需要 root | rootless 下 clone 带 CLONE_NEW* 会 EPERM | 加 CLONE_NEWUSER + uid map（复杂度高） |
| 无 seccomp 继承控制 | worker 继承母体的"无 seccomp"状态 | 母体在 clone 前装 seccomp（worker 继承，只能加严不能放松） |
| ~~无 cgroup 限额~~ | ✅ 已用 per-worker 叶子 + `clone3(CLONE_INTO_CGROUP)` 解决（见 7.1） | 限额已可设；OOM/throttle 的"执法生效"实测待补 |

> **进展**：协议、隔离、宿主 PID 直传、**热内存共享**、**cgroup 资源围栏**均已落地。剩下的都是"把它接进真实运行时"的工程活（state.json 收养、seccomp 继承、rootless）。

---

## 九、实现状态清单

| 能力 | 对应代码 | 状态 |
|---------|-----------|------|
| 母体守护 + AF_UNIX 触发 | cmd/zygote/main.go、zygote/protocol.go | ✅ 已实现 |
| 一句 clone 出 6 间房 worker | zygote/spawn.go（Cloneflags） | ✅ 已实现，strace 实测 |
| 宿主 PID 直传 | cmd.Process.Pid（母体无 PID ns） | ✅ 已实现，NSpid 实测两字段 |
| 宿主侧 client | cmd/spawn/main.go | ✅ 已实现 |
| 共享母体热内存 | zygote/warm.go（memfd + MAP_SHARED） | ✅ 已实现，smaps 实测 |
| per-worker cgroup 围栏 | zygote/cgroup.go（clone3 CLONE_INTO_CGROUP） | ✅ 已实现，执法待实测 |
| worker 自证负载 | cmd/worker/main.go | ✅ 已实现 |
| 母体 OCI spec（进容器） | zygote/spec.go | 🔜 装置已写，待跑 |
| state.json 收养（runc 纳管 worker） | — | 🔜 后续 |
| worker 日志落文件 | — | 🔜 后续 |
| 延迟稳态数（p50/p95） | — | 🔜 后续 |
