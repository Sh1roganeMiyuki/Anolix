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
│                                   fork#1 (re-exec)               │
│                                         │                        │
│                                         ▼                        │
│                              ┌──────────────────────┐            │
│                              │ intermediate (短命)   │            │
│                              │                      │            │
│                              │ unshare(6 ns)        │            │
│                              │ fork#2 → worker      │            │
│                              │ 写 host PID → pipe   │            │
│                              │ exit                 │            │
│                              └──────────┬───────────┘            │
│                                         │                        │
│                                   fork#2 (worker)                │
│                                         │                        │
│                                         ▼                        │
│                              ┌──────────────────────┐            │
│                              │ worker               │            │
│                              │ PID=1 in new PID ns  │            │
│                              │ 独立 MNT/UTS/IPC/    │            │
│                              │ NET/CGROUP ns        │            │
│                              │ 执行 payload 命令     │            │
│                              └──────────────────────┘            │
│                                                                  │
│  intermediate 退出后 → worker 被 reparent 到 init/subreaper       │
│  mother 不持有 worker 的 wait 责任 → 无僵尸问题                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 二、文件结构与职责

```
zygote/
  protocol.go     通信协议：SpawnRequest/Response + 帧编解码
  spawn.go        核心机制：double-fork + unshare 的实现
  spec.go         母体容器 OCI spec 生成（无 PID ns、有 caps、无 seccomp）

cmd/
  zygote/main.go  母体守护进程入口（也承载 intermediate 模式）
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
{"host_pid": -1, "error": "unshare 失败: operation not permitted"}
```

### 3.3 对照 bytedanceDoc

| 文档设计 | 本实现 | 差异原因 |
|---------|--------|---------|
| 魔数 0x5A59 | "ZYGO" (4字节) | 更易调试（ASCII 可读） |
| Python AF_UNIX | Go net.Listen("unix") | 语言选择 |
| 写 state.json 注册 | 返回 host PID（注册为后续迭代） | 先验证核心机制 |

---

## 四、Double-Fork 协议详解

### 4.1 为什么是 double-fork

单次 fork 不够的三个原因：

1. **unshare(CLONE_NEWPID) 的语义**：调用者自身不进入新 PID ns，只有"此后创建的子进程"才进入。所以必须 unshare 后再 fork 一次，worker 才是新 PID ns 的 1 号。

2. **per-worker 独立 ns**：如果母体直接 unshare 再 fork N 次，N 个 worker 共享同一个 PID ns（第一个是 1 号，其余是 2、3…号）。每次 spawn 造一个一次性 intermediate，才能让每个 worker 拥有独立的 ns 集合。

3. **生命周期解耦**：intermediate 退出后 worker 被 reparent，母体不需要 wait() worker。母体是常驻进程，如果持有所有 worker 的 wait 责任，会产生僵尸管理负担。

### 4.2 Go 实现的特殊处理

Go runtime 是多线程的，直接 fork() 不安全（子进程只继承调用线程，其余线程的状态不一致）。

解法：**re-exec 模式**
- 母体不直接 fork，而是 `exec.Command("/proc/self/exe", "--zygote-intermediate")`
- intermediate 是一个全新的 Go 进程（单线程启动）
- intermediate 内部 `runtime.LockOSThread()` + `syscall.Unshare()` + `syscall.ForkExec()`
- ForkExec 创建 worker（新进程，立即 exec payload）→ 安全

CoW 共享情况：
- intermediate 与母体共享二进制只读页（exec 后的 file-backed 映射）
- worker 与 intermediate 共享地址空间（fork 的 CoW）
- **局限**：worker exec 新程序后，母体的堆内存不再共享
- **未来迭代**：若要真正共享母体预热堆（如 torch 模型），worker 不能 exec，
  必须从母体直接 fork 并继续执行 Go 代码（需要 raw clone，不用 exec）

### 4.3 时序图

```
mother              intermediate           worker
  │                      │                    │
  │─── exec.Command ────►│                    │
  │    (fork#1 等价)      │                    │
  │                      │                    │
  │─── stdin: JSON ─────►│                    │
  │                      │                    │
  │                      │── LockOSThread     │
  │                      │── Unshare(6 ns)    │
  │                      │                    │
  │                      │── ForkExec ───────►│
  │                      │   (fork#2)         │
  │                      │                    │── exec payload
  │◄── pipe: hostPID ────│                    │
  │                      │── exit(0)          │
  │── Wait() 回收 ───────│                    │
  │                      ×                    │── 独立运行
  │                                           │   (reparent to init)
  │◄── response: {host_pid} ──── client       │
```

---

## 五、母体容器 Spec 设计

### 5.1 与普通沙箱的差异

母体是"受信基础设施"，不是"被隔离的不可信负载"：

| 维度 | 普通沙箱 | 母体 | 原因 |
|------|---------|------|------|
| PID ns | 有 | **无** | fork 返回值 = 宿主 PID |
| Caps | 清空 | CAP_SYS_ADMIN | unshare 需要 |
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
# 1. 构建
CGO_ENABLED=0 go build -o rootfs/zygote ./cmd/zygote
go build -o spawn ./cmd/spawn

# 2. 准备 bundle（需要 root）
sudo mkdir -p /tmp/anolix-zygote/logs
# 生成 config.json（可用 Go 工具或手动 runc spec）

# 3. 启动母体
sudo runc run -d --bundle <bundle> mother-1

# 4. Spawn worker
sudo ./spawn --socket /tmp/anolix-zygote/spawn.sock -- /probe
```

---

## 六、Namespace 隔离保证

Worker 获得的 6 间房（由 intermediate 的 unshare 创建）：

| Namespace | Flag | Worker 内效果 |
|-----------|------|--------------|
| Mount | CLONE_NEWNS | 独立挂载树（继承 intermediate 的副本） |
| PID | CLONE_NEWPID | worker = PID 1；其子进程 = 2, 3… |
| UTS | CLONE_NEWUTS | 独立主机名 |
| IPC | CLONE_NEWIPC | 独立共享内存/消息队列 |
| Network | CLONE_NEWNET | 无网络（只有 down 的 loopback） |
| Cgroup | CLONE_NEWCGROUP | 独立 cgroup 视图 |

验证手段（worker 内部）：
- `getpid()` 应返回 1
- `/proc/self/status` 的 NSpid 应有两个字段（宿主 PID + ns 内 PID）
- `hostname` 应与母体不同
- `ip addr` 应只有 lo（且 DOWN）

---

## 七、已知局限与后续迭代

| 局限 | 影响 | 后续方案 |
|------|------|---------|
| worker exec 新程序 → 不共享母体堆 | CoW 仅限二进制页 | 实现"no-exec worker"模式（raw clone + Go 续行） |
| 无 state.json 注册 | runc list/kill/delete 管不到 worker | 实现收养逻辑（写 runc state 目录） |
| 母体需要 root | rootless 下 unshare 会 EPERM | 加 CLONE_NEWUSER + uid map（复杂度高） |
| 无 seccomp 继承控制 | worker 继承母体的"无 seccomp"状态 | intermediate 在 fork 前装 seccomp（worker 继承） |
| 无 cgroup 限额 | worker 无资源围栏 | intermediate 写 cgroup.procs 迁移 worker |

---

## 八、与 bytedanceDoc 的对照总结

| 文档概念 | 本实现对应 | 状态 |
|---------|-----------|------|
| 母体容器 rl-mother-v3 | zygote mother（runc 容器，无 PID ns） | ✅ 已实现 |
| zygote_mother_v3.py | cmd/zygote/main.go | ✅ 已实现 |
| AF_UNIX /run/spawn.sock | bind-mount socket 目录 | ✅ 已实现 |
| 0x5A59 触发 | "ZYGO" 魔数 + JSON | ✅ 已实现 |
| double-fork + unshare | zygote/spawn.go | ✅ 已实现 |
| host_pid 直传 | pipe 回传 + 响应 JSON | ✅ 已实现 |
| runc_spawn_v3.py | cmd/spawn/main.go | ✅ 已实现 |
| 写 state.json 收养 | — | 🔜 后续 |
| worker 日志 /worker-logs/ | bind-mount logs 目录 | ✅ 骨架已有 |
| ~50ms spawn 延迟 | 待实测 | 🔜 后续 |
