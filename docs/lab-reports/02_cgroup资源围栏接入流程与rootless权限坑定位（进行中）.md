# 02_cgroup 资源围栏接入流程与 rootless 权限坑定位

> 研究文档系列 02 ｜ 2026-09-24
> 项目：Anolix（轻量沙箱运行时核心，Go + runc）
> 环境：WSL2 Ubuntu / 内核 6.18 / runc 1.3.4 / cgroup v2 统一层级
> 本文所有数字与输出均来自本机真实运行，无推断值；推导项标注【推导】，未完成项标注【待续】。

---

## 背景

01 篇完成了 seccomp 模块——约束沙箱"能做什么系统调用"。本篇开始第二个模块：**cgroup 资源围栏**——约束沙箱"能用多少资源"（内存 / 进程数 / CPU）。

沿用同一套三段链方法：

```
【声明层】policy.json              —— 项目自定义
【翻译层】launcher → OCI spec      —— 项目自定义
【执法层】runc → 内核 cgroup v2    —— 内核固定
```

验证标准：每个限额都要在**内核接口文件里读到数字**，并在超限时观察到**执法行为**（fork 被拒 / OOM / CPU 节流）——只看配置不算数。

本篇记录四件事：模块接入、rootless 权限坑、pids 围栏取证、CPU 围栏取证。其中 pids 的取证过程本身又是一次"错误签名"分析：**同一条 fork 循环命令先后给出三种不同的失败文案**，分别对应 seccomp 层、白名单缺口、cgroup 层——文案本身就是分层判据。

---

## 一、模块接入

### 1.1 声明层：policy 新增 resources

examples/policy.json 基线：

```json
"resources": {
  "memoryLimitBytes": 67108864,
  "pidsLimit": 20,
  "cpuQuotaMicros": 20000,
  "cpuPeriodMicros": 100000
}
```

即：内存 64 MiB、进程数上限 20、CPU 每 100ms 允许 20ms（0.2 核）。

校验逻辑（`config.Resources.Validate`）：数值下限、周期范围 [1ms, 1s]；周期未配置时回退默认 100ms。

### 1.2 翻译层：OCI spec 映射

`launcher.applyResourceLimits` → OCI `LinuxResources`：

| policy 字段 | OCI 字段 | 内核接口文件 |
| --- | --- | --- |
| memoryLimitBytes | LinuxMemory.Limit | memory.max |
| pidsLimit | LinuxPids.Limit | pids.max |
| cpuQuotaMicros / cpuPeriodMicros | LinuxCPU.Quota / Period | cpu.max 左值 / 右值 |

单测覆盖（config / launcher 双侧），生成的 bundle/config.json 可静态核对。【项目自定义】

### 1.3 故障 A：旧二进制 + 严格解析

现象：用未重编译的二进制跑新 policy，解析层直接拒绝：

```
unknown field "resources"
```

原因：config 解析使用 `DisallowUnknownFields`，旧二进制不认识新增字段。重编译（`go build -o anolix ./cmd/anolix`）后通过。

教训：解析层报错，先核对"跑的是哪份二进制"，再怀疑代码逻辑。

---

## 二、rootless 权限坑：cgroup 建立被拒

### 2.1 原始报错

非 root 运行、policy 带限额：

```
ERRO[0000] runc run failed: unable to start container process: unable to apply cgroup configuration:
rootless needs no limits + no cgrouppath when no permission is granted for cgroups:
mkdir /sys/fs/cgroup/anolix-d89938e9fb84: permission denied
```

### 2.2 两分支行为（源码级定位）

runc 的 cgroup 建立走 cgroups 库 fs2 实现，建立失败时的 rootless 分支（摘录，关键分支）：

```go
if createErr != nil {
    if config.Rootless && config.Path == "" {
        if !needAnyControllers(config.Resources) {
            return cgroups.ErrRootless                  // 无任何限额：容忍，容器照跑（无专属 cgroup）
        }
        return fmt.Errorf("rootless needs no limits + no cgrouppath ...")  // 有限额：硬报错
    }
    return createErr
}
```

结论："以前能跑、现在报错"的分界不是改坏了代码，而是从"没有任何限额要求"变成"有要求"——**无要求时可静默跳过，有要求时没有可写的位置就拒绝启动**。【runc 实现】

### 2.3 落点规则与环境事实

落点规则（runc 未指定 cgroupsPath 时）：

```
目标路径 = cgroup2 挂载点 + dir(自身所在 cgroup) + 容器ID
```

本机会话位于 `/init.scope`，`dir()` 后为 `/`，因此目标是 `/sys/fs/cgroup/anolix-<id>`（顶层）。【runc 实现】

本机实测环境：

| 对象 | 观察值 |
| --- | --- |
| /sys/fs/cgroup（顶层） | dr-xr-xr-x root:root（555，不给普通用户写） |
| 当前会话 cgroup | /init.scope |
| 委派子树 | user@1000.service/app.slice，属主 sh1rogane，控制器含 cpu memory pids |

即：普通用户身份在该环境下没有可写的位置来建容器 cgroup。

runc 官方测试矩阵（tests/integration/cgroups.bats）覆盖了对应象限：无限制 + 无权限 → 跳过且成功；有限制 + 无权限 → 报错。行为属预期设计，不是本项目缺陷。

### 2.4 权限尝试：chmod 是死路（实测记录）

| 尝试 | 结果 |
| --- | --- |
| 普通用户 `chmod -x /sys/fs/cgroup` | Operation not permitted（非属主；且方向也错——缺的是 w，不是去掉 x） |
| `sudo chmod +w /sys/fs/cgroup` | 命令成功：555 → 755，但只加到属主位（umask 滤掉 group/other 的 w）；普通用户身份重跑依然 mkdir 被拒 |
| 对照：`chmod o+w` 自己名下的 app.slice | 成功（0755→0757，随后已还原）——"改得动"的前提是"地归你" |

两个出口由此收敛：

1. **换身份**：sudo（rootful）——顶层对 root 可写；本篇后续全部执法实验均走此路线；
2. **换地块**：先进入委派子树（如 `systemd-run --user --scope`），在属自己的 cgroup 上开工。【待续】

（写本文时实测 /sys/fs/cgroup 已回到 dr-xr-xr-x；目录时间戳显示此后发生过重新挂载，早前的权限改动已复位。）

### 2.5 三条路线对照（实测进度）

| 路线 | 身份 | 落点 | 结果 |
| --- | --- | --- | --- |
| 普通 shell | sh1rogane | /sys/fs/cgroup/anolix-*（顶层） | mkdir 被拒（有限额时硬报错） |
| sudo | root | 同上 | 容器正常启动，限额写入生效 |
| systemd-run --user --scope | sh1rogane | app.slice/anolix-* | 已见可建 cgroup（早期实验）；限额读数【待续】 |

### 2.6 一次失败点漂移（待复核）

另一次非 root 运行，失败点不在 mkdir 而在更后面：

```
failed to write <pid>: write /sys/fs/cgroup/anolix-5aeeb66be7fb/cgroup.procs: permission denied
```

说明失败点会随 /sys/fs/cgroup 当时的权限状态变化（该次运行时的权限状态未完整记录，之后挂载已复位为 555）。【待复核：在固定环境下复现一次，确认失败点漂移的条件。】

---

## 三、pids 围栏实证：同一条命令的三种失败文案

### 3.1 实验装置

容器内 fork 循环，尝试开出 60 个后台进程（sudo 路线，限额真实写入）：

```bash
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c 'i=0; while [ $i -lt 60 ]; do /bin/busybox sleep 60 & i=$((i+1)); done; echo "fork 结束，活着等你看"; sleep 45'
```

同一条命令在名单修复过程中先后跑出三种文案，逐一归因如下。

### 3.2 第一种文案：无名 errno（seccomp 层盖章）

```
sh: can't fork: No error information
```

`No error information` 是 libc 对**不认识的 errno 值**的兜底文案（musl 的写法；glibc 会写 `Unknown error <n>`）。内核定义的 errno 都有名字（EAGAIN、ENOMEM……），因此这个 errno 不是内核产生的——它是 policy 的 `errnoRet=1145`（01 篇的哨兵值）：**fork 在 syscall 入口就被 seccomp 的 defaultAction 盖章，内核的 pids 检查根本没执行到**。

根因：放行名单里只有 `clone`/`clone3`，没有 `fork`(57)/`vfork`(58)。Go/glibc 的进程创建走 clone，而 busybox（musl 静态构建）的 fork 路径走 57/58 号——**名单按名字匹配，clone 的放行不覆盖 fork**。runc/libseccomp 对名单中无法识别的名字是静默忽略的，因此这个缺口没有任何报错提示。

点验（补名单后）：`sysc 57` 由"盖章"变为"放行"，且输出出现父子两份（fork 的真实语义）：

```
syscall 57 成功: 返回值=11
syscall 57 成功: 返回值=0
```

### 3.3 第二种文案：/dev/null（open(2) 缺口）

补上 fork/vfork 后重跑，文案变为：

```
sh: can't open '/dev/null': No error information
```

POSIX 规定后台作业的 stdin 必须改接 /dev/null（否则后台进程会抢终端输入），这一步发生在 fork 之后、exec 之前，动作是一次 `open("/dev/null")`。名单里有 `openat` 但没有 `open`，而 musl 的 `open()` 在 x86-64 上走的是 2 号系统调用——**openat 的放行不覆盖 open**，于是子进程在这一步被盖章后死亡。

伴随的两个现场证据（/proc 采样）：

| 对象 | 观察值 | 含义 |
| --- | --- | --- |
| 子进程 | State = Z（zombie），cmdline 为空 | 死在 exec 之前，且未被回收 |
| 父 shell | State = R；`/proc/<pid>/syscall` 连续 20 次采样均为 `running` | 纯用户态忙循环，`wait` 从未被调用 |

即"漏一条名单"的第三种死法：不报错、不退出，而是**挂死**。修复：名单补 `open`。

### 3.4 第三种文案：EAGAIN（pids 围栏真正上手）

补上 open 后重跑同一条命令：

```
sh: can't fork: Resource temporarily unavailable
```

`Resource temporarily unavailable` 是 **EAGAIN(11)** 的标准文案——有名字的错误，来自内核资源检查：`pids.current` 触到 `pids.max=20` 后，fork 在 clone 执行路径中被 pids 控制器拒绝。【内核固定】

两个细节：

- 输出只有一行错误、`echo "fork 结束"` 未打印：busybox ash 将 fork 失败视为致命错误，脚本当场终止（失败点约在第 19~20 个子进程处【推导：pids.max=20 扣除 shell 自身】）；
- 已创建的 sleep 子进程随容器 init 退出由 runc 一并清理，未在宿主残留。

至此同一条命令的三种文案完成归因：**无名 errno = seccomp 盖章；/dev/null 无名 errno = 白名单缺口（open）；EAGAIN = cgroup pids 围栏**。

### 3.5 三层签名小抄

| 观测到的错误 | 出自哪层 | 语义 |
| --- | --- | --- |
| 1145（libc 兜底文案，无名 errno） | seccomp defaultAction | syscall 入口被盖章（策略章，01 篇哨兵值） |
| EAGAIN 11（Resource temporarily unavailable） | cgroup pids.max | 内核资源检查：允许 fork，但生不出来 |
| ENOSYS 38（Function not implemented） | 真内核 / libseccomp 内建伪造 | 号码表外或内核不支持（01 篇发现一） |

判据：**有名字的错误来自内核，无名字的错误来自策略层**。

---

## 四、CPU 围栏实证：throttle 的读数

### 4.1 为什么 CPU 围栏没有错误输出

三道围栏的执法方式不同，可观测签名也因此不同：

| 围栏 | 执法方式 | 可观测签名 |
| --- | --- | --- |
| memory.max | OOM kill | 进程被杀（退出码 137）+ dmesg 记录【待续】 |
| pids.max | 拒绝新增 | fork 返回 EAGAIN（第三章） |
| cpu.max | throttle：周期内配额用尽即冻结，下周期再放行 | **无任何错误输出**，只能读 cpu.stat |

因此 CPU 围栏的取证不能等报错，必须主动布点读计数器。

### 4.2 实验装置

容器内起两个纯用户态死循环（0 个系统调用，seccomp 不参与），前台 sleep 30 撑出观测窗口：

```bash
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c '
    echo "=== CPU 燃烧开始，持续 30 秒 ==="
    # 起 2 个死循环后台进程把核占满
    i=0; ( while :; do i=$((i+1)); done ) &
    j=0; ( while :; do j=$((j+1)); done ) &
    /bin/busybox sleep 30
    echo "=== 燃烧结束 ==="
  '
```

第二终端在窗口内盯读数（cgroup 由 sudo 创建，但目录权限 755，读取无需 sudo）：

```bash
c=$(ls -dt /sys/fs/cgroup/anolix-* | head -1)
watch -n 1 "cat $c/cpu.stat"
```

容器内输出：

```
=== CPU 燃烧开始，持续 30 秒 ===
=== 燃烧结束 ===
```

### 4.3 原始读数

```
Every 1.0s: cat /sys/fs/cgroup/anolix-3aee011e67c6/cpu.stat          LAPTOP-BF0J00M9: Thu Sep 24 19:02:41 2026

usage_usec  5965001
user_usec  5949531
system_usec  15470
nice_usec  0
nr_periods  297
nr_throttled  297
throttled_usec  53302860
nr_bursts  0
burst_usec  0
```

### 4.4 数字自洽性核对

配置值：cpu.max = `20000 100000`（0.2 核，由 policy 映射写入）。【项目自定义 → 内核固定】

| 核对项 | 计算 | 观察值 | 结论 |
| --- | --- | --- | --- |
| 窗口长度 | nr_periods 297 × 100ms = 29.7s | 燃烧窗口 30s | 周期配置真实生效 |
| CPU 发放量 | 29.7s × 0.2 = 5.94s = 5,940,000µs | usage_usec = 5,965,001µs | 偏差 0.4%，配额真实生效 |
| 限流频率 | — | nr_throttled = 297 = nr_periods | **每个周期都被限流**（需求持续超配额） |
| 冻结总量【推导】 | 需求 2 核 × 29.7s = 59.4s，减去发放 5.94s = 53.46s | throttled_usec = 53,302,860µs | 偏差 0.3%；throttled_usec 为全部被冻任务的合计时间 |
| 时间分布 | user_usec / usage_usec = 99.7% | system_usec 仅 15,470µs | 与"纯用户态循环"的装置设计一致 |

五项读数互相咬合：配额（0.2 核）、周期（100ms）、限流频率（每周期）、冻结总量（需求−发放）全部对得上——**cpu.max 的执法行为完成实证**。

### 4.5 结论

CPU 围栏的签名是"读数"而不是"报错"：usage_usec 的斜率恒为配额比例、nr_throttled 持续累加。这与 06 讲义的模型一致——throttle 是"跑跑停停"，不是降频，也不是拒绝。【内核固定】

---

## 五、观测窗口坑（方法论）

cgroup 目录随容器生命周期存在与消失，"何时读"与"读什么"同等重要：

1. **目录生命周期**：容器退出 → cgroup 目录被清理 → 宿主机读不到（`ls: cannot access '/sys/fs/cgroup/anolix-*': No such file or directory`）。读数必须在存活窗口内完成；本篇 CPU 实验用前台 `sleep 30` 撑窗口；
2. **fork 失败会直接终止 shell**：循环触到 pids 上限后仅输出一行 `can't fork` 且容器随即退出——不能用"fork 出来的命令"撑窗口，要用**内建 wait**（不需要 fork）；
3. **后台 SIGTTIN**：命令尾挂 `&` 且 stdin 仍接终端时，容器进程组读终端会被 SIGTTIN 停住（Stopped (tty input)），残留 job 干扰后续。处理：`</dev/null` 或前台运行，残留用 `kill %N` 清理。

---

## 六、结论与待续

### 6.1 阶段性结论

1. 三段链全部打通：声明（policy）→ 翻译（OCI spec）→ 执法（内核接口文件读数 + 执法行为），pids 与 cpu 两道围栏均拿到第一手证据；memory 围栏【待续】；
2. rootless + 有限额 + 无权限 = 硬报错；rootless + 无限额 = 静默跳过。分界条件：是否需要控制器。【runc 实现】
3. 权限坑的出口只有两条：**换身份**（sudo）或**换地块**（委派子树）；chmod 修不了（方向也不对）；
4. 同一条命令的三种失败文案证明：**错误文案本身就是分层判据**——无名 errno 指向策略层，有名字的错误指向内核层。

### 6.2 教训

- **二进制版本是第一嫌疑**：解析层报错（unknown field）先查"跑的哪个二进制"；
- **"配置了" ≠ "生效了"**：限额证据是内核文件里的数字与执法行为（EAGAIN / OOM / 节流读数），不是 policy.json 里的声明；
- **白名单缺口有三种死法**：解析层报错（unknown field）、seccomp 盖章（无名 errno）、挂死（zombie + 用户态自旋）——同一条"漏一条"的根因，表现完全不同；且 runc 对名单中无法识别的名字静默忽略，拼写错误同样无声；
- **CPU 围栏不产生错误输出**：观测必须主动布点（cpu.stat），等报错会永远等不到；
- **实验装置要包含"读取窗口"**：cgroup 对象只在容器存活期存在，涉及存活时间的失败模式（fork 失败即退）要先想清楚撑窗口的手段。

### 6.3 待续实验清单

| # | 实验 | 观测点 | 状态 |
| --- | --- | --- | --- |
| 1 | pids 三件套读数（窗口内读取，命令见附录） | pids.max / pids.current / pids.events | 待执行 |
| 2 | 内存超限 | 容器退出码 137 + dmesg "Memory cgroup out of memory" | 待执行 |
| 3 | 委派子树对照（systemd-run --user --scope） | 容器 cgroup 落在 app.slice 下、三件套可读可写 | 待执行 |
| 4 | 2.6 失败点漂移复现 | 固定环境复现一次 | 待复核 |
| 5 | 探针判据与 errnoRet 对齐 | probe 的 blocked() 只认 EPERM/ENOSYS，errnoRet=1145 下误报 fail | 待实现 |
| 6 | 第二批工具：内存炸弹 / CPU 忙循环专用探针 | 替代 busybox 的粗验证 | 未开始 |

---

## 附录：本模块使用过的关键命令

```bash
# 重编译（或 abuild，见 ~/.bash_aliases）
go build -o anolix ./cmd/anolix

# pids 实验（fork 循环，sudo 路线）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c 'i=0; while [ $i -lt 60 ]; do /bin/busybox sleep 60 & i=$((i+1)); done; sleep 45'

# pids 三件套（长窗口版：19 个子进程 + 内建 wait 撑窗口）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 120s -- \
  /bin/busybox sh -c 'i=0; while [ $i -lt 19 ]; do /bin/busybox sleep 60 & i=$((i+1)); done; echo "--- 窗口打开 ---"; wait'
# 第二终端（窗口内）：
c=$(sudo ls -dt /sys/fs/cgroup/anolix-* | head -1); sudo cat "$c"/pids.max "$c"/pids.current "$c"/pids.events

# CPU 实验（双燃烧进程 + sleep 30 撑窗口）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs --timeout 60s -- \
  /bin/busybox sh -c 'i=0; ( while :; do i=$((i+1)); done ) & j=0; ( while :; do j=$((j+1)); done ) & /bin/busybox sleep 30'
# 第二终端（窗口内）：
c=$(ls -dt /sys/fs/cgroup/anolix-* | head -1); watch -n 1 "cat $c/cpu.stat"

# 名单点验（容器内按号码观测）
sudo ./anolix run --policy examples/policy.json --rootfs ./rootfs -- /sysc 57   # fork：放行则输出父子两份
```

源码参照位置（本地缓存，已 gitignore）：

- `.tmpgm/github.com/opencontainers/cgroups@v0.0.4/`（fs2 实现：Apply 两分支、defaultpath 落点规则、CreateCgroupPath）
- `.tmprs/` 中 runc 1.3.4（tests/integration/cgroups.bats 四象限测试矩阵）
