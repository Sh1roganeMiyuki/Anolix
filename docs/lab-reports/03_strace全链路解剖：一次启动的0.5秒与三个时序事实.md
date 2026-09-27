# 03_strace 全链路解剖：一次启动的 0.5 秒与三个时序事实

> 研究文档系列 03 ｜ 2026-09-27
> 项目：Anolix（轻量沙箱运行时核心，Go + runc）
> 环境：WSL2 Ubuntu / 内核 6.18 / runc 1.3.4 / strace（-f -tt）
> 本文所有数字与输出均来自本机一次真实抓取（trace.log，10,881 行），无推断值；单次样本，非统计基线。

---

## 背景

01 篇从**错误码**取证（seccomp 拦截的三种来源），02 篇从**读数**取证（cgroup 接口文件与 dmesg）。本篇换第三个角度：**时序**。

用 strace 把一次完整启动录下来，回答三个此前只有纸面结论的问题：

1. seccomp 过滤器到底在**什么位置**被装载？装载的覆盖语义是什么？
2. "宿主看不到容器挂载"在系统调用层长什么样？
3. 一次冷启动**多久**，时间花在哪几段？

顺带把 01 篇故障 B（白名单漏 runtime 依赖）的调用点钉到具体行号。

---

## 一、装置与读法

### 1.1 抓取命令

```bash
strace -f -tt -o trace.log ./anolix run --rootfs ./rootfs -- /probe
```

rootless、内置默认策略（无 `--policy`）。`-f` 跟所有线程与子进程，`-tt` 带微秒时间戳。

### 1.2 读法三原则

1. 一行 = 时间 + 进程 + 调用 + 结果；
2. 只看大动作：`execve` / `unshare` / `mount` / `seccomp` / `prctl`；
3. 满屏的 `futex` / `nanosleep` 是多线程程序的心跳（互相唤醒、打盹），初读全部跳过。

### 1.3 进程谱系（pid → 角色）

| pid | 角色 | 依据 |
| --- | --- | --- |
| 216235–216243 | anolix（Go 线程组） | L1 execve("./anolix") |
| 216245 | runc run（工头） | L760 execve("/usr/sbin/runc") |
| 216258 / 216259 | runc 的自重新执行与 nsexec 阶段 | L4004 execve("/proc/self/fd/6", ["runc","init"])；L4248/4267 unshare |
| 216260 | **容器 init**（最终 execve /probe） | L9900 execve("/probe") |
| 216261+ | 各阶段的 Go 线程 | futex/nanosleep 心跳 |

---

## 二、全链路时间线与冷启动基线

| 时刻 | 事件 | 行 | 责任层 |
| --- | --- | --- | --- |
| 51.550444 | anolix 启动；Go 开场白（读 THP 页大小 L4、`prctl(PR_SET_VMA…)` 命名 arena） | L1-40 | 项目自定义 |
| 51.579144 | `mkdir /tmp/anolix-bundle-1373909550` | L450 | 项目自定义 |
| 51.583766 | 写 `config.json` | L540 | 项目自定义 |
| 51.592136 | `execve /usr/sbin/runc`（`--root /run/user/1000/anolix-runc` = rootless 状态目录） | L760 | 项目自定义 → 行业实现 |
| 51.785833 | `unshare(CLONE_NEWUSER)` | L4248 | runc 实现 |
| 51.787653 | `unshare(CLONE_NEWNS\|NEWCGROUP\|NEWUTS\|NEWIPC\|NEWPID\|NEWNET)` | L4267 | runc 实现 |
| 51.832758 | `mount("", "/", MS_REC\|MS_SLAVE)` | L5301 | runc 实现 |
| 51.834230 | `mount(rootfs, rootfs, MS_BIND\|MS_REC)`（自绑定造挂载点） | L5331 | runc 实现 |
| 51.843604+ | 挂 proc / tmpfs(/dev) / devpts / shm / mqueue | L5538-6775 | runc 实现 |
| 51.981032 | `prctl(PR_SET_NO_NEW_PRIVS, 1)` | L8619 | runc 实现 |
| 51.981181 | init 管道写 `procReady`；父侧 `prlimit64(RLIMIT_NOFILE, 1024)` | L8622 / L8643 | runc 实现（RLIMIT 来自 spec） |
| **52.022723** | **`seccomp(SET_MODE_FILTER, SPEC_ALLOW, {len=159}) = 0`** | L9596-9599 | libseccomp（库） |
| 52.023490 | `fstatfs(13) = PROC_SUPER_MAGIC`；`fstat(13)`（"验房"检查） | L9611-9623 | runc 实现 |
| 52.033334 | `execve("/probe")` | L9900 | runc 实现 |
| 52.036317+ | 探针开场白（同一套 Go 启动序列，在过滤器之下全部成功） | L9913-9955 | 项目自定义 |
| 52.091564+ | bundle 清理（`unlinkat` 步行删除） | L10760-10801 | 项目自定义 |
| 52.095925 | 全线程 `exit_group(0)`，退出码 0 | L10880 | — |

**分段基线**：

| 段 | 区间 | 耗时 |
| --- | --- | --- |
| anolix 自身（启动 → execve runc） | 51.550444 → 51.592136 | **42 ms** |
| runc（execve runc → execve probe） | 51.592136 → 52.033334 | **441 ms** |
| 探针运行 + 收尾（execve probe → anolix 退出） | 52.033334 → 52.095925 | **63 ms** |
| **到容器 init** | 51.550444 → 52.033334 | **483 ms** |
| **全程** | — | **545 ms** |

过滤器规模：**159 条 BPF 指令**（`len=159`）。【测量】

---

## 三、时序事实一：过滤器装载在 execve 前的最后一步

### 3.1 顺序

```
PR_SET_NO_NEW_PRIVS (51.9810)
   → init 管道握手 procReady (51.9811)
   → seccomp 装载 (52.0227)
   → 10.6 ms 后 execve("/probe") (52.0333)
```

### 3.2 覆盖语义：没有 TSYNC 为什么仍然完备

装载 flags 只有 `SECCOMP_FILTER_FLAG_SPEC_ALLOW`，**没有 `TSYNC`**——即过滤器只装到调用线程上。这不是漏洞：紧随的 `execve` 会丢弃其余所有线程，只留调用线程（携带过滤器）；之后 `clone` 出的线程全部继承。【内核固定：过滤器线程级、execve 后保留、clone 继承】

### 3.3 为什么必须最后装

装载之后到 execve 之间的调用（`fstatfs`/`fstat` 验房、`close`、`futex`），以及探针的整个开场白，**都在过滤器之下执行**。名单必须覆盖它们。

**01 篇故障 B 的调用点在此钉死**：L9611 的 `fstatfs`（确认 /proc 是 procfs）就是"ensure /proc/... is on procfs: function not implemented"那条报错的来源——名单缺 `fstatfs` 时，这一步被拦截。

### 3.4 区分"能力探测"与"装载"

`seccomp(SET_MODE_STRICT)`→EINVAL、`SET_MODE_FILTER`+NULL→EFAULT、`GET_ACTION_AVAIL`、`GET_NOTIF_SIZES` 出现两次（L1314-1337：runc run 载入 libseccomp.so 时；L5014-5036：runc init 内）——这些是**库的自检**，不是装载；真正的装载只有 L9596 一次。

---

## 四、时序事实二：挂载传播被切断（宿主不可见）

| 动作 | 行 | 语义 |
| --- | --- | --- |
| `mount("", "/", MS_REC\|MS_SLAVE)` | L5301 | runc 未指定 rootfsPropagation 时的默认（rslave：只收不发），从源头切断向宿主传播【runc 实现】 |
| rootfs 链各级 `MS_PRIVATE` | L5314-5327 | 对非挂载点返回 EINVAL 属预期噪音（L5318） |
| `mount(rootfs, rootfs, MS_BIND\|MS_REC)` | L5331 | 自绑定造出挂载点，`pivot_root` 的前提【runc 实现】 |
| 挂载目标走 `/proc/thread-self/fd/N` + `fsmount`/`open_tree` | L5418 / L8675-8683 | 新挂载 API 防路径竞争；`open_tree` 失败 EPERM 后回退 O_PATH，是 rootless 无 CAP_SYS_ADMIN 的降级路径 |

**结果**：全程 **0 次 EBUSY、0 次 umount**；清理段（L10760+）是 Go `os.RemoveAll` 的步行删除，一次成功。与 02 篇的结构结论一致：bundle 不是挂载点、挂载随 mount namespace 消失，因此删目录不会报"设备或资源忙"。

---

## 五、时序事实三：rootless cgroup 容忍分支的 syscall 级证据

| 行 | 调用与结果 | 含义 |
| --- | --- | --- |
| L1440 | `statfs("/sys/fs/cgroup") = CGROUP2_SUPER_MAGIC` | cgroup v2 统一层级【内核固定】 |
| L1465 | `newfstatat("/sys/fs/cgroup/anolix-3e10afe62f83") = ENOENT` | 专属 cgroup 不存在 |
| L1469 | `openat2(..., "anolix-…/cgroup.freeze") = ENOENT` | 探测 freeze/kill 能力 |
| L4194 | `openat2(..., "cgroup.controllers") = 14` | 枚举控制器成功 |
| L4199 / L4201 | `openat2(..., "cgroup.subtree_control", O_WRONLY) = EACCES`（两次） | 写不进去 |

无限额 → 写失败被容忍 → **跳过专属 cgroup，容器照跑，退出码 0**。这是 02 篇"两分支行为"（无要求静默跳过 / 有要求硬报错）的运行期证据。

---

## 六、探针的"开场白"：execve 换人的脚印

同一句"这台机器的大页多大？"（读 `/sys/kernel/mm/transparent_hugepage/hpage_pmd_size`）在日志中出现 **4 次**：

| 谁 | 行 | 是否在过滤器下 |
| --- | --- | --- |
| anolix | L4 | 否（沙箱外） |
| runc run | L867 | 否 |
| runc init | L4384 | 否（尚未装载） |
| **probe** | **L9916** | **是** |

原因：`execve` 的语义是**用新程序替换当前进程的全部内容**，旧状态全部作废；Go 运行时的开场白（圈内存、起线程、装信号处理器、建 epoll 总机）每次启动都要重跑一遍。因此**名单必须覆盖"最后一个进场者"的全部内务**——语言决定名单。

旁证：`prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, …, " Go: heap reservation")` 等命名串（L9920-9953）使 trace 自解释；信号注册（`rt_sigaction(SIGSYS)`，L4624-4628）与 SIGURG 抢占（`tgkill(…, SIGURG)`，L8654-8658）同样可见。

---

## 七、结论与教训

### 7.1 结论

1. 三档时序：`PR_SET_NO_NEW_PRIVS` → 过滤器装载（159 条指令）→ execve；装载到 execve 仅 10.6 ms，其间与之后的所有调用都在过滤下；
2. 覆盖语义靠"execve 丢弃其余线程"补全，不依赖 TSYNC；
3. 挂载传播默认 rslave + 各级 private + rootfs 自绑定，是"宿主不可见、删除无 EBUSY"的机制来源；
4. rootless 无限额时 cgroup 写失败被容忍（EACCES → 跳过），与 02 篇源码级结论互证；
5. 冷启动基线（单次）：到容器 init 483 ms，其中 runc 段 441 ms。

### 7.2 教训

- **冷启动数字必须分段记**：42 / 441 / 63 ms 三段，才能回答"慢在哪"；
- **"相同调用重复出现"不是异常**，是 execve 换人的脚印（`grep -c hpage_pmd_size trace.log` = 4）；
- **装载 flags 决定覆盖语义**：读 trace 时先看 flags，再谈"装没装全"；
- **01 篇的报错要回到调用点**：`fstatfs` 验房（L9611）就是"function not implemented"的现场。

### 7.3 待续

| # | 项 | 目的 |
| --- | --- | --- |
| 1 | 多轮抓取取 p50/p95 | 把单次基线变成统计基线 |
| 2 | rootful + 带 resources 的对照 trace | 观察 cgroup 建立路径（mkdir/写文件）进入时间线 |
| 3 | SIGKILL / 超时路径的 trace | 补 02 篇"孤儿与清理"的书面空白 |

---

## 附录：命令

```bash
# 抓取（更好读：-y 给 fd 带路径，-s 200 少截断）
strace -f -tt -y -s 200 -o trace.log ./anolix run --rootfs ./rootfs -- /probe

# 快速切片：只看大动作
grep -n 'execve(\|unshare(\|seccomp(\|MS_SLAVE\|MS_BIND\|PR_SET_NO_NEW_PRIVS' trace.log

# 换人脚印计数（应为 4）
grep -c hpage_pmd_size trace.log

# 过滤器装载点
grep -n 'SET_MODE_FILTER.*len=' trace.log
```
