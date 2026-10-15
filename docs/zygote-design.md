# Zygote 预热 Fork 机制：架构设计文档

> 本文件随代码实现同步更新，记录架构决策与对照关系。
> 对照来源：`notes/bytedanceDoc.md` 方案 B（runc Spawn / fork / zygote）。

---

## 一、整体架构

```
┌─────────────────────────────────────────────────────────────────┐
│  宿主                                                            │
│                                                                  │
│  ┌──────────┐    AF_UNIX     ┌──────────────────────────────┐   │
│  │ spawn    │───────────────►│ zygote mother (常驻守护)      │   │
│  │ client   │◄───────────────│                              │   │
│  └──────────┘   host PID     │  已预热（模拟 import torch）  │   │
│                              │  不在 PID namespace 中        │   │
│                              └──────────┬───────────────────┘   │
│                                         │                        │
│                       clone(CLONE_NEW* 6 间房)                   │
│                       （一步到位，无中间进程）                     │
│                                         │                        │
│                                         ▼                        │
│                              ┌──────────────────────┐            │
│                              │ worker               │            │
│                              │ PID=1 in new PID ns  │            │
│                              │ 独立 MNT/UTS/IPC/    │            │
│                              │ NET/CGROUP ns        │            │
│                              │ exec payload 命令     │            │
│                              └──────────────────────┘            │
│                                                                  │
│  worker 是 mother 的直接子进程 → mother 用后台 goroutine Wait 收尸 │
└─────────────────────────────────────────────────────────────────┘
```

> **演进说明**：旧版走 double-fork + unshare（re-exec 一个 Go 中间进程），strace 实测那段
> Go 冷启动约 25ms，是纯税。现版改用 `SysProcAttr.Cloneflags` 一步 clone，去掉中间进程。
> 旧 double-fork 版已入 git 历史。

---

## 二、文件结构与职责

```
zygote/
  protocol.go     通信协议：SpawnRequest/Response + 帧编解码
  spawn.go        核心机制：SysProcAttr.Cloneflags 一步 clone 出带 6 间房的 worker
  spec.go         母体容器 OCI spec 生成（无 PID ns、有 caps、无 seccomp）

cmd/
  zygote/main.go  母体守护进程入口
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
  "binary": "/probe",
  "args": ["hold", "60"],
  "env": ["PATH=/bin"],
  "cwd": "/",
  "worker_id": "worker-1"
}

// 响应（成功）
{"host_pid": 12345}

// 响应（失败）
{"host_pid": -1, "error": "clone 失败: operation not permitted"}
```

### 3.3 对照 bytedanceDoc

| 文档设计 | 本实现 | 差异原因 |
|---------|--------|---------|
| 魔数 0x5A59 | "ZYGO" (4字节) | 更易调试（ASCII 可读） |
| Python AF_UNIX | Go net.Listen("unix") | 语言选择 |
| 写 state.json 注册 | 返回 host PID（注册为后续迭代） | 先验证核心机制 |

---

## 四、Worker 生成机制：从 double-fork 到直接 clone

### 4.1 文档为什么用 double-fork（Python 路径）

bytedanceDoc 的 intermediate + double-fork 不是随意设计，是被机制逼出来的：

1. **unshare 改的是调用者自己**：`unshare(CLONE_NEWNS/UTS/IPC/NET/CGROUP)` 让调用进程**立即**进入新 ns；`unshare(CLONE_NEWPID)` 让调用进程的**下一个子进程**成为新 PID ns 的 1 号。母体不能去 unshare 自己（否则母体被污染）→ 必须借道一个一次性中间进程。
2. **Python 的 `os.fork()` 不带 flags**：没法一步 clone 出带 ns 的孩子，只能 `unshare()` + `fork()` 两步 → 中间进程是自然结果。
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
- 这不是"Go 比 Python 高级"，是**运行时暴露的 API 不同**：C 也能一步（runc 的 `nsexec.c` 就是 clone 带 flags）；Python 要走一步 clone 得下到 ctypes/preexec_fn，不惯用。

### 4.3 演进：旧版 re-exec 的税

旧 double-fork 版为绕开"Go 多线程不能安全 raw fork"，re-exec 了一个 Go 中间进程。代价（strace 实测）：

| 段 | 时长(strace 下) | 性质 |
|---|---|---|
| fork#1 + exec intermediate | ~5.6ms | 可省 |
| **intermediate 的 Go runtime 冷启动** | **~25ms** | **纯税，可省** |
| unshare(6ns) | ~6.5ms | 新版由 clone flags 承担 |
| fork#2 + exec worker | ~5.3ms | 保留 |

新版砍掉中间进程 → 那 ~25ms 的 Go-init 税直接消失。（数字为 `strace -f` 下，含插桩膨胀，看相对比例；且各段放大不均——syscall 多的段被放大更狠。）

### 4.4 新版时序图

```
mother                              worker
  │                                   │
  │── clone(CLONE_NEW* 6 间房) ──────►│
  │   (cmd.Start，一步)                │── 出生即 pid 1
  │                                   │── exec payload
  │◄── cmd.Process.Pid = host PID ────│
  │                                   │
  │── response: {host_pid} ── client  │── 独立运行
  │                                   │
  │   (后台 goroutine: cmd.Wait 收尸)  │
```

### 4.5 代价：收尸责任回到母体

旧版靠中间进程退出触发 reparent，母体不用管 worker 死活。新版 worker 是母体的**直接子进程**：

- 母体必须自己 `Wait`，否则 worker 退出后留僵尸。
- 实现：`SpawnWorker` 里起一个后台 goroutine `cmd.Wait()`（见 `spawn.go`）。
- 这是小账（一个 goroutine），换掉的是 ~25ms 的 Go-init 税。

---

## 五、母体容器 Spec 设计

### 5.1 与普通沙箱的差异

母体是"受信基础设施"，不是"被隔离的不可信负载"：

| 维度 | 普通沙箱 | 母体 | 原因 |
|------|---------|------|------|
| PID ns | 有 | **无** | clone 返回值 = 宿主 PID |
| Caps | 清空 | CAP_SYS_ADMIN | clone 带 CLONE_NEW* 需要 |
| Seccomp | 严格白名单 | **关闭** | 需要全量 syscall |
| NNP | true | **false** | caps 需要 |
| MNT/UTS/IPC/NET/CGROUP | 有 | 有 | 母体自身仍需部分隔离 |

### 5.2 Socket 通信路径

```
宿主侧：  <socketDir>/spawn.sock     ← client 连接这里
容器内：  /run/spawn/spawn.sock      ← 母体监听这里
          ↑ 同一个文件（bind-mount）
```

### 5.3 启动方式

```bash
# 1. 构建（母体若要放进容器 rootfs，需静态编译）
CGO_ENABLED=0 go build -o rootfs/zygote ./cmd/zygote
go build -o bin/spawn ./cmd/spawn

# 2. 宿主直跑（实验最简路径，需 root：clone 带 CLONE_NEW* 要 CAP_SYS_ADMIN）
sudo ./bin/zygote --socket /tmp/anolix-zygote.sock --warm 64

# 3. Spawn worker
sudo ./bin/spawn --socket /tmp/anolix-zygote.sock -- /bin/busybox sleep 30

# 4. 验证 worker 隔离
cat /proc/<host_pid>/status | grep NSpid   # 应见两个字段：宿主 PID + ns 内 PID(=1)
```

> 母体进 runc 容器（用 `zygote/spec.go` 生成 bundle）是后续迭代；当前实验走宿主直跑最省事。

---

## 六、Namespace 隔离保证

Worker 获得的 6 间房（由 `clone` 的 `CLONE_NEW*` flags 一步创建）：

| Namespace | Flag | Worker 内效果 |
|-----------|------|--------------|
| Mount | CLONE_NEWNS | 独立挂载树（继承母体的副本） |
| PID | CLONE_NEWPID | worker = PID 1；其子进程 = 2, 3… |
| UTS | CLONE_NEWUTS | 独立主机名 |
| IPC | CLONE_NEWIPC | 独立共享内存/消息队列 |
| Network | CLONE_NEWNET | 无网络（只有 down 的 loopback） |
| Cgroup | CLONE_NEWCGROUP | 独立 cgroup 视图 |

验证手段（worker 内部 / 宿主侧）：
- 宿主侧 `cat /proc/<host_pid>/status | grep NSpid` → 两个字段（已实测：`NSpid: 1126656 1`）
- worker 内 `getpid()` 应返回 1
- worker 内 `hostname` 应与母体不同
- worker 内 `ip addr` 应只有 lo（且 DOWN）

---

## 七、已知局限与后续迭代

| 局限 | 影响 | 后续方案 |
|------|------|---------|
| **worker 走 clone+exec → 不共享母体堆** | `--warm` 的预热内存对 worker 零贡献；CoW 仅限二进制页 | 实现"no-exec worker"：raw clone 后原地继续跑（Go 需 C helper / 单线程设计），才是真 zygote |
| 无 state.json 注册 | runc list/kill/delete 管不到 worker | 实现收养逻辑（写 runc state 目录） |
| 母体需要 root | rootless 下 clone 带 CLONE_NEW* 会 EPERM | 加 CLONE_NEWUSER + uid map（复杂度高） |
| 无 seccomp 继承控制 | worker 继承母体的"无 seccomp"状态 | 母体在 clone 前装 seccomp（worker 继承，只能加严不能放松） |
| 无 cgroup 限额 | worker 无资源围栏 | 宿主侧为 worker 建叶子 cgroup、写 cgroup.procs 迁移 |

> **最重要的一条**：当前实现证明了"协议通 + 隔离对 + 宿主 PID 直传"，但**还没拿到 zygote 的核心价值（CoW 共享热内存）**——因为 worker exec 了新程序。这是下一版要攻的点。

---

## 八、与 bytedanceDoc 的对照总结

| 文档概念 | 本实现对应 | 状态 |
|---------|-----------|------|
| 母体容器 rl-mother-v3 | zygote mother（当前宿主直跑，无 PID ns） | ✅ 已实现 |
| zygote_mother_v3.py | cmd/zygote/main.go | ✅ 已实现 |
| AF_UNIX /run/spawn.sock | socket 路径可配（宿主直跑用 /tmp） | ✅ 已实现 |
| 0x5A59 触发 | "ZYGO" 魔数 + JSON | ✅ 已实现 |
| double-fork + unshare | **改用 Cloneflags 一步 clone**（旧版入 git 历史） | ✅ 已实现（更优） |
| host_pid 直传 | cmd.Process.Pid（母体无 PID ns） | ✅ 已实现，NSpid 实测两字段 |
| runc_spawn_v3.py | cmd/spawn/main.go | ✅ 已实现 |
| 写 state.json 收养 | — | 🔜 后续 |
| worker 日志 /worker-logs/ | spec 里 bind-mount（宿主直跑暂未接） | 🔜 后续 |
| ~50ms spawn 延迟 | 待脱掉 strace 实测 | 🔜 后续 |
| **CoW 共享母体热内存** | worker 仍 exec → 未共享 | 🔜 后续（no-exec worker） |
